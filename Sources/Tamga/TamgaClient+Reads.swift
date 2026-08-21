import Foundation

/// The read half of the licence, policy and machine resources.
///
/// Everything here is a plain `GET` of a resource this SDK previously could
/// only observe indirectly -- through a validation verdict, a checkout file, or
/// not at all.
extension TamgaClient {
    // MARK: - Licences and policies

    /// Fetches a licence by id.
    ///
    /// **`attributes.key` comes back in cleartext, and this route is not
    /// confined to the credential's own licence.** The server gates it on the
    /// `license.read` permission and the account, and on nothing else: it never
    /// narrows the query to the licence the caller authenticated as. A licence
    /// token holding `license.read` can therefore read *any* licence in the
    /// same account, key included. That is a server-side property this SDK
    /// cannot fix and does not paper over -- do not treat this endpoint as a
    /// safe way to expose licence data to a semi-trusted client, and do not log
    /// the result. Reported upstream.
    public func getLicense(_ licenseId: String) async throws -> License {
        let data = try await transport.getJSON(["licenses", licenseId])
        return License.fromResource(
            try Self.decode(DataEnvelope<LicenseAttributes>.self, from: data).data)
    }

    /// Fetches a policy by id.
    ///
    /// **Not reachable with a licence-key credential -- use
    /// `getLicensePolicy(_:)` instead.** This route is gated on the
    /// `policy.read` permission, and a licence token does not hold it: its
    /// permission set carries `license.read`, `machine.*` and `process.*` but
    /// not `policy.read`, so every call from an embedded client gets a `403`.
    /// The two routes return the identical resource; only the permission they
    /// ask for differs, which is the entire reason both are exposed here.
    ///
    /// `Policy.heartbeatDuration` read from either route is the real heartbeat
    /// window -- see `HeartbeatScheduler.interval(forWindowSeconds:)`.
    ///
    /// `maxMemory` and `maxDisk` are not on the response at all, so this cannot
    /// tell you those two limits however you ask. See `Policy`.
    public func getPolicy(_ policyId: String) async throws -> Policy {
        let data = try await transport.getJSON(["policies", policyId])
        return Policy.fromResource(
            try Self.decode(DataEnvelope<PolicyAttributes>.self, from: data).data)
    }

    /// Fetches the policy attached to a licence.
    ///
    /// **This is the one an embedded client can call.** It is gated on
    /// `license.read`, which a licence token holds, whereas `getPolicy(_:)`
    /// asks for `policy.read`, which it does not -- so the same resource is a
    /// `403` through one route and a `200` through the other. It is also the
    /// more natural call anyway: a client holds a licence id, not a policy id.
    ///
    /// Every licence has exactly one policy -- the column is not nullable, so
    /// there is no "licence with no policy" case to handle. A `404` here means
    /// the licence is missing, or its policy row is.
    ///
    /// Carries the same reach as `getLicense(_:)`: gated on `license.read` and
    /// the account, never narrowed to the caller's own licence.
    public func getLicensePolicy(_ licenseId: String) async throws -> Policy {
        let data = try await transport.getJSON(["licenses", licenseId, "policy"])
        return Policy.fromResource(
            try Self.decode(DataEnvelope<PolicyAttributes>.self, from: data).data)
    }

    // MARK: - Machines

    /// Fetches a machine by id.
    ///
    /// **This is the route that makes `HeartbeatStatus.dead` observable.** It
    /// reads the stored row rather than deriving the status from a write it
    /// just made, so the status is a genuine staleness verdict and
    /// `nextHeartbeatAt` is computed against `policy.heartbeatDuration` rather
    /// than the 600s fallback. A `.dead` branch is finally reachable code here
    /// -- unlike against a ping response, where it never was.
    ///
    /// `.dead` still does not mean the row was culled. See `HeartbeatStatus`.
    public func getMachine(_ machineId: String) async throws -> Machine {
        let data = try await transport.getJSON(["machines", machineId])
        return Machine.fromResource(
            try Self.decode(DataEnvelope<MachineAttributes>.self, from: data).data)
    }

    /// Lists the account's machines, one **offset-paginated** page at a time.
    ///
    /// **This is the only offset-paginated route in this SDK.** It is the only
    /// one that reports `meta.page`, so it is the only one whose page count is
    /// known rather than inferred. Everything else -- components, a machine's
    /// processes, entitlements -- is keyset with a synthesized cursor, or not
    /// paginable at all. Advance this one with `pageInfo.nextPageNumber`.
    ///
    /// Filters are comma-joined into a single value per key rather than sent as
    /// repeated keys; see `ListMachinesOptions.queryItems` for why. There is
    /// **no fingerprint filter** -- pass the fingerprint as
    /// `ListMachinesOptions.query` and compare `Machine.fingerprint` on the
    /// results, which is a substring match across three columns rather than an
    /// equality test.
    public func listMachines(
        options: ListMachinesOptions = ListMachinesOptions()
    ) async throws -> OffsetPage<Machine> {
        let data = try await transport.getJSON(["machines"], query: options.queryItems)
        let envelope = try Self.decode(ListPageEnvelope<MachineAttributes>.self, from: data)
        return OffsetPage(pageInfo: envelope.meta?.pageInfo,
                          items: envelope.data.map(Machine.fromResource))
    }

    /// Lists a machine's processes, one keyset-paginated page at a time.
    ///
    /// Keyset like `listComponents`, **not** offset like `listMachines`: this
    /// route reports no `meta.page` at all, so the cursor is synthesized from
    /// page fullness the same way. That asymmetry between the machine
    /// collection and its own sub-collections is real server behaviour.
    public func listMachineProcesses(
        machineId: String,
        options: ListOptions = ListOptions()
    ) async throws -> Page<MachineProcess> {
        let data = try await transport.getJSON(["machines", machineId, "processes"],
                                               query: Self.pageQuery(options))
        let envelope = try Self.decode(ListEnvelope<ProcessAttributes>.self, from: data)
        return Page(nextCursor: Self.synthesizeCursor(envelope.data, options: options),
                    items: envelope.data.map(MachineProcess.fromResource))
    }

    /// Updates a machine's reported attributes.
    ///
    /// **Omitting a field leaves it alone; it does not clear it.** The server
    /// merges every column with `COALESCE`, so no value you can send through
    /// here nulls out `name`, `ip`, `hostname`, `platform` or `metadata`.
    ///
    /// **Do not trust the heartbeat fields on the response.** The update's
    /// `RETURNING` clause does not join the policy, so `heartbeatStatus` and
    /// `nextHeartbeatAt` come back computed against the 600s fallback rather
    /// than `policy.heartbeatDuration` -- so a `getMachine(_:)` of the same
    /// machine a second earlier can disagree with it. Read them from
    /// `getMachine(_:)`.
    ///
    /// **This response is also the counterexample to "a write can never say
    /// `DEAD`".** That rule holds for ping, reset and create because each one
    /// writes `last_heartbeat_at` and then judges the machine by the timestamp
    /// it just set. `PATCH` is a write that never touches that column, so it
    /// judges an untouched timestamp and can absolutely answer `.dead` --
    /// against the 600s fallback rather than the policy window, which is the
    /// second reason not to read the status from here.
    ///
    /// **Not scoped to the caller's own licence.** A licence-key credential
    /// holds `machine.update` and is in the permitted role set, and no machine
    /// route applies a licence-scope check, so a licence key can update any
    /// machine in the account -- the same reach `deleteMachine(_:)` has.
    /// Reported upstream; do not describe this surface as licence-scoped.
    ///
    /// Changing `cores`, `memory` or `disk` re-computes the licence's running
    /// totals server-side, so an update can move a licence over a limit that a
    /// later validation then reports.
    ///
    /// - Throws: `TamgaError.transport` before any request is made if
    ///   `options` would change nothing -- an empty `attributes` object is a
    ///   round trip that cannot do anything, and silently making it look like
    ///   an update succeeded is worse than saying so.
    public func updateMachine(
        _ machineId: String,
        options: UpdateMachineOptions
    ) async throws -> Machine {
        guard !options.isEmpty else {
            throw TamgaError.transport(
                message: "updateMachine was called with no fields set. Omitting every field "
                    + "changes nothing server-side -- fields are merged, not replaced.",
                underlying: nil)
        }
        let data = try await transport.patchJSON(["machines", machineId],
                                                 body: options.requestBody)
        return Machine.fromResource(
            try Self.decode(DataEnvelope<MachineAttributes>.self, from: data).data)
    }
}
