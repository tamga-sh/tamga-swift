import Foundation

/// Re-activating a machine whose fingerprint is already registered.
extension TamgaClient {
    /// Activates a machine, treating an already-registered fingerprint as the
    /// machine it names rather than as a failure.
    ///
    /// `activateMachine(_:scope:)` rethrows `409 FINGERPRINT_TAKEN` unchanged,
    /// which is correct but is a dead end: the caller learns the machine exists
    /// and is given no handle on it. That is the common case, not an edge --
    /// every reinstall, every cache wipe, every second launch on a device whose
    /// fingerprint is stable re-sends a fingerprint the server already knows.
    /// This method closes that loop: on the conflict it looks the machine up
    /// and continues with it, so activation becomes idempotent.
    ///
    /// The validation step is identical either way, so an over-limit verdict
    /// still throws `TamgaError.machineOverLimit` -- but **an existing machine
    /// found this way is never deleted on that verdict.** Rolling back would
    /// destroy a seat this call did not create and the caller did not ask to
    /// give up. Only a machine this call created itself is rolled back.
    ///
    /// ## The lookup is scoped to `options.licenseId`, and that is load-bearing
    ///
    /// A machine resource carries no `license_id` and no `relationships` block
    /// -- the server emits neither -- so nothing downstream can check which
    /// licence a machine belongs to. The scoping has to happen in the query.
    ///
    /// It costs nothing, because **a genuine re-activation is always inside the
    /// caller's own licence**. Whether the fingerprint collides is decided by
    /// the policy's machine-uniqueness strategy, and all three include the
    /// caller's own rows: `UNIQUE_PER_LICENSE` matches on `license_id`
    /// directly, `UNIQUE_PER_POLICY` matches every licence sharing the policy
    /// (the caller's among them), and `UNIQUE_PER_ACCOUNT` matches the whole
    /// account. So re-sending a fingerprint already on *this* licence raises the
    /// `409` under every strategy, and a licence-scoped search finds it every
    /// time.
    ///
    /// What an account-wide search would add is only the case the server
    /// refuses on purpose: the same fingerprint on a *different* licence, which
    /// is seat-sharing and is precisely what the two wider scopes exist to
    /// prevent. Returning that machine would leave the caller pinging and
    /// checking out a machine its licence does not own, while its own
    /// `machinesCount` stayed at zero -- and, with no `license_id` on the
    /// resource, unable to notice. So that case rethrows the conflict instead.
    ///
    /// ## When it cannot find the machine, it rethrows the conflict
    ///
    /// Two ways that happens:
    ///
    /// - **The conflicting machine is on another licence**, per above. This is
    ///   the `409` doing its job, not a gap.
    /// - **The exact match fell off the page.** The lookup reads a single page
    ///   of `TamgaClient.defaultPageSize`, the server's maximum. There is no
    ///   fingerprint filter on the machine collection; the closest thing is a
    ///   substring search spanning `name`, `hostname` and `fingerprint`, so a
    ///   licence holding more than 100 machines whose name, hostname or
    ///   fingerprint contains this fingerprint as a substring can push the real
    ///   one onto a second page this SDK does not fetch.
    ///
    /// Either way the original `409` is what you get, unchanged -- never a
    /// synthesized "not found". `TamgaError.isFingerprintTaken` identifies it.
    ///
    /// Since the API patch a same-licence conflict names the existing machine
    /// in `meta.machineId`; that is tried first with one `getMachine`, and the
    /// licence-scoped search below is the fallback.
    ///
    /// - Throws: everything `activateMachine(_:scope:)` throws, with the same
    ///   meanings, plus a rethrown `409 FINGERPRINT_TAKEN` when the lookup
    ///   above finds nothing.
    public func reactivateMachine(
        _ options: CreateMachineOptions,
        scope: Scope? = nil
    ) async throws -> ActivationResult {
        do {
            return try await activateMachine(options, scope: scope)
        } catch let error as TamgaError where error.isFingerprintTaken {
            guard let existing = try await resolveTakenFingerprint(error, options: options) else {
                throw error
            }
            return try await validateExistingActivation(existing, options: options, scope: scope)
        }
    }

    /// Finds the machine a `409 FINGERPRINT_TAKEN` refused to duplicate.
    ///
    /// Fast path first: a same-licence conflict names the machine in
    /// `meta.machineId` (`TamgaError.conflictingMachineId`), so one
    /// `getMachine` replaces the search. The search is the fallback for a
    /// pre-patch server, a conflict that carried no `meta`, the race where
    /// the named row was deleted between the two calls (the read `404`s),
    /// and the fast path returning a machine whose fingerprint does not
    /// actually match -- the fast path trusts `meta.machineId` but not
    /// the row it points at, so it is re-checked exactly like the search's
    /// own result is. In every fallback case the search finds nothing and
    /// the caller rethrows the `409`, never a synthesized `404`. Only a
    /// same-licence conflict carries `meta`, so an adopted machine is always
    /// the caller's own seat; the search keeps the licence scoping documented
    /// on `reactivateMachine` for the same reason.
    private func resolveTakenFingerprint(
        _ conflict: TamgaError,
        options: CreateMachineOptions
    ) async throws -> Machine? {
        if let machineId = conflict.conflictingMachineId {
            do {
                let existing = try await getMachine(machineId)
                if existing.fingerprint == options.fingerprint {
                    return existing
                }
            } catch let error as TamgaError where error.isNotFound {
                // Fall through to the search.
            }
        }
        return try await findMachine(fingerprint: options.fingerprint, licenseId: options.licenseId)
    }

    /// Finds the licence's machine with exactly this fingerprint, or `nil`.
    ///
    /// The machine collection has no fingerprint filter. `filter[q]` is the
    /// nearest thing, and it is an `ILIKE '%term%'` across `name`, `hostname`
    /// and `fingerprint` -- a substring match over three columns, not an
    /// equality test on one. **Both steps err towards a superset**, which is
    /// what makes the pair sound: a machine whose fingerprint equals the term
    /// always contains it, so the exact match is on the page if it is anywhere,
    /// and the client-side equality filter then discards every near-miss the
    /// search swept in. It can fail to find a machine; it cannot return the
    /// wrong one.
    ///
    /// Terms over 200 characters are truncated server-side before the pattern
    /// is built. That only widens the match, so a long fingerprint still finds
    /// itself -- it just sweeps in more near-misses for the filter to discard.
    ///
    /// Scoped to one licence, and one page. See `reactivateMachine(_:scope:)`
    /// for why the scoping is deliberate rather than a limitation.
    func findMachine(fingerprint: String, licenseId: String) async throws -> Machine? {
        let page = try await listMachines(options: ListMachinesOptions(
            pageSize: Self.defaultPageSize,
            licenseIds: [licenseId],
            query: fingerprint))
        return page.items.first { $0.fingerprint == fingerprint }
    }

    /// Runs the validation half of an activation against a machine that already
    /// existed, without ever deleting it.
    ///
    /// Mirrors `activateMachine`'s validation step exactly, minus the rollback:
    /// this machine predates the call, so an over-limit verdict is a fact about
    /// the licence rather than something this call caused, and deleting it
    /// would surrender a seat the caller never offered up.
    private func validateExistingActivation(
        _ machine: Machine,
        options: CreateMachineOptions,
        scope: Scope?
    ) async throws -> ActivationResult {
        let validation: ValidationResult
        do {
            validation = try await validateById(options.licenseId,
                                                options: ValidateOptions(scope: scope))
        } catch {
            throw TamgaError.activationValidationFailed(machine: machine, underlying: error)
        }
        if validation.meta.code.isOverLimit {
            throw TamgaError.machineOverLimit(validation.meta)
        }
        return ActivationResult(machine: machine, meta: validation.meta)
    }
}
