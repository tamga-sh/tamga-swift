import Foundation

/// Machine, component and process endpoints.
extension TamgaClient {
    // MARK: - Machines

    /// Registers a machine against a license.
    ///
    /// **Creation does enforce policy limits, but only sometimes.** The
    /// server runs the limit check through the policy's overage strategy: under
    /// `NO_OVERAGE` an over-limit create is refused with a `422` carrying
    /// `MACHINE_LIMIT_EXCEEDED`, `CORE_LIMIT_EXCEEDED`, `MEMORY_LIMIT_EXCEEDED`
    /// or `DISK_LIMIT_EXCEEDED`, while under `ALLOW_ACCESS` /
    /// `ALLOW_1_25X_OVERAGE` the same create succeeds and the limit surfaces
    /// later, at validation. Both paths therefore have to be handled.
    ///
    /// `TamgaError.limitValidationCode` normalizes those create-time codes onto
    /// the validate-time `ValidationCode` vocabulary; `activateMachine` does it
    /// for you, and is the better entry point when the desired behaviour is
    /// "reject an over-limit activation".
    ///
    /// A fingerprint already registered within the policy's uniqueness scope is
    /// refused with `409 FINGERPRINT_TAKEN` before any limit is considered.
    public func createMachine(_ options: CreateMachineOptions) async throws -> Machine {
        let data = try await transport.postJSON(["machines"], body: options.requestBody)
        return Machine.fromResource(
            try Self.decode(DataEnvelope<MachineAttributes>.self, from: data).data)
    }

    /// Deletes a machine, freeing its seat.
    public func deleteMachine(_ machineId: String) async throws {
        try await transport.delete(["machines", machineId])
    }

    /// Registers a machine and validates the license in one step, rejecting an
    /// over-limit activation from either side of the server's two limit checks.
    ///
    /// This is a composite, not a single endpoint: create, then validate, then
    /// delete on an over-limit verdict. **Both limit paths are live and which
    /// one fires is the policy's choice, not the caller's.** Under `NO_OVERAGE`
    /// the create itself is refused with a `422` limit code and no row is ever
    /// written; under `ALLOW_ACCESS` / `ALLOW_1_25X_OVERAGE` the create succeeds
    /// and only validation reports the limit, so without the rollback that
    /// activation would leave a row behind still consuming a seat. Both surface
    /// here as the same `machineOverLimit`, with the create-time code normalized
    /// onto the validation vocabulary (`MACHINE_LIMIT_EXCEEDED` ->
    /// `TOO_MANY_MACHINES`, `CORE_LIMIT_EXCEEDED` -> `TOO_MANY_CORES`,
    /// `MEMORY_LIMIT_EXCEEDED` -> `TOO_MUCH_MEMORY`, `DISK_LIMIT_EXCEEDED` ->
    /// `TOO_MUCH_DISK`).
    ///
    /// - Throws: `TamgaError.machineOverLimit` if either check reported an
    ///   over-limit condition. On the validate-time path the machine has already
    ///   been deleted by then; on the create-time path no machine was ever
    ///   created, so there is nothing to roll back and no delete is issued.
    ///   Either way the meta says which limit was exceeded.
    ///
    ///   `TamgaError.activationValidationFailed` if the validation call itself
    ///   failed. **The machine is NOT deleted in that case** and is handed back
    ///   on the error, because a network blip is not a verdict about the
    ///   license and deleting on one would destroy a seat for no reason. This
    ///   follows `tamga-go` rather than `tamga-java`: Java rolls back because
    ///   throwing leaves it no way to return the machine, and Swift has one.
    ///
    ///   Any other `TamgaError` from the create is rethrown unchanged --
    ///   notably `409 FINGERPRINT_TAKEN`, which is a re-activation, not a limit.
    public func activateMachine(
        _ options: CreateMachineOptions,
        scope: Scope? = nil
    ) async throws -> ActivationResult {
        let machine = try await createMachineNormalizingLimits(options)
        let validation: ValidationResult
        do {
            validation = try await validateById(options.licenseId,
                                                options: ValidateOptions(scope: scope))
        } catch {
            // Deliberately NOT rolled back. Whether the machine is permitted is
            // unknown, and a transient failure is not grounds to destroy a seat
            // the license may well be entitled to. The machine goes back to the
            // caller, who can retry validation or delete it.
            throw TamgaError.activationValidationFailed(machine: machine, underlying: error)
        }

        if validation.meta.code.isOverLimit {
            await deleteIgnoringFailure(machine.id)
            throw TamgaError.machineOverLimit(validation.meta)
        }
        return ActivationResult(machine: machine, meta: validation.meta)
    }

    /// Creates a machine, converting a create-time policy-limit `422` into the
    /// same `machineOverLimit` a validate-time limit produces.
    ///
    /// No rollback is attempted here on purpose: the server refused before
    /// writing a row, so there is no seat to reclaim and a `DELETE` against an
    /// id that was never issued would only produce a second, misleading error.
    fileprivate func createMachineNormalizingLimits(
        _ options: CreateMachineOptions
    ) async throws -> Machine {
        do {
            return try await createMachine(options)
        } catch let error as TamgaError {
            guard let meta = error.overLimitMeta else { throw error }
            throw TamgaError.machineOverLimit(meta)
        }
    }

    /// Deletes a machine during activation rollback, ignoring a failure to do
    /// so.
    ///
    /// The caller is already throwing; a rollback failure must not mask the
    /// original cause. The worst case is an orphaned machine row an operator
    /// can see and remove, whereas a swallowed root cause leaves nothing to act
    /// on.
    fileprivate func deleteIgnoringFailure(_ machineId: String) async {
        try? await deleteMachine(machineId)
    }

    /// Sends a heartbeat ping for a machine.
    ///
    /// Use `HeartbeatScheduler` rather than driving this by hand.
    ///
    /// This is a bare idempotent state write, so it is retried automatically
    /// after a `429` -- a throttled heartbeat that was silently dropped would
    /// eventually get the machine culled.
    public func pingHeartbeat(machineId: String) async throws -> Machine {
        let data = try await transport.postJSON(
            ["machines", machineId, "actions", "ping-heartbeat"], body: nil)
        return Machine.fromResource(
            try Self.decode(DataEnvelope<MachineAttributes>.self, from: data).data)
    }

    /// Resets a machine's heartbeat, returning it to the not-started state.
    ///
    /// **Not callable with a license-key credential.** The server gates this on
    /// the caller's *role*, not on a permission: only admin, developer, product
    /// and environment tokens pass. `AuthTransport.licenseKey`,
    /// `.basicLicenseKey` and any other license-scoped credential always get
    /// `403 FORBIDDEN` here, so do not present it to an embedded client as a
    /// recovery path -- it is not one, even though it is the only server-side
    /// way to unstick a machine whose `heartbeat_jid` is wedged.
    public func resetHeartbeat(machineId: String) async throws -> Machine {
        let data = try await transport.postJSON(
            ["machines", machineId, "actions", "reset-heartbeat"], body: nil)
        return Machine.fromResource(
            try Self.decode(DataEnvelope<MachineAttributes>.self, from: data).data)
    }

    /// Generates a signed offline proof for a machine over the supplied
    /// dataset.
    ///
    /// Verify it later with `MachineProof` against the same dataset. The
    /// signature covers a canonical, recursively key-sorted rendering, so the
    /// dataset must round-trip byte-identically.
    ///
    /// **Not callable with a license-key credential.** Like `resetHeartbeat`
    /// this is role-gated server-side, and a license-scoped credential is not in
    /// the permitted set -- it always returns `403 FORBIDDEN`, despite holding
    /// the `machine.proofs.generate` permission. Proofs have to be minted by an
    /// admin/developer/product/environment token and shipped to the device.
    public func generateOfflineProof(
        machineId: String,
        dataset: [String: JSONValue] = [:]
    ) async throws -> OfflineProofResult {
        let data = try await transport.postJSON(
            ["machines", machineId, "actions", "generate-offline-proof"],
            body: .object(["meta": .object(["dataset": .object(dataset)])])
        )
        let envelope = try Self.decode(
            DataMetaEnvelope<MachineAttributes, ProofMeta>.self, from: data)
        return OfflineProofResult(machine: Machine.fromResource(envelope.data),
                                  proof: envelope.meta?.proof)
    }

    // MARK: - Components and processes

    /// Registers a component against a machine.
    public func createComponent(_ options: CreateComponentOptions) async throws -> Component {
        let data = try await transport.postJSON(["components"], body: options.requestBody)
        return Component.fromResource(
            try Self.decode(DataEnvelope<ComponentAttributes>.self, from: data).data)
    }

    /// Lists a machine's components, one keyset-paginated page at a time.
    ///
    /// Keyset pagination genuinely works on this route, unlike
    /// `listEntitlements`. When `options.limit` is left at zero the request
    /// still names an explicit page size -- `TamgaClient.defaultPageSize`, the
    /// server maximum -- because the server's own default of 25 is invisible on
    /// the wire and would make `nextCursor` read a full page as a short one and
    /// stop after 25 rows.
    public func listComponents(
        machineId: String,
        options: ListOptions = ListOptions()
    ) async throws -> Page<Component> {
        let data = try await transport.getJSON(["machines", machineId, "components"],
                                               query: Self.pageQuery(options))
        let envelope = try Self.decode(ListEnvelope<ComponentAttributes>.self, from: data)
        return Page(nextCursor: Self.synthesizeCursor(envelope.data, options: options),
                    items: envelope.data.map(Component.fromResource))
    }

    /// Registers a running process against a machine.
    public func createProcess(_ options: CreateProcessOptions) async throws -> MachineProcess {
        let data = try await transport.postJSON(["processes"], body: options.requestBody)
        return MachineProcess.fromResource(
            try Self.decode(DataEnvelope<ProcessAttributes>.self, from: data).data)
    }

    /// Sends a heartbeat ping for a process.
    ///
    /// Use `ProcessHeartbeatScheduler` rather than driving this by hand.
    public func pingProcess(processId: String) async throws -> MachineProcess {
        let data = try await transport.postJSON(
            ["processes", processId, "actions", "ping"], body: nil)
        return MachineProcess.fromResource(
            try Self.decode(DataEnvelope<ProcessAttributes>.self, from: data).data)
    }
}
