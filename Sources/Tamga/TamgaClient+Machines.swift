import Foundation

/// Machine, component and process endpoints.
extension TamgaClient {
    // MARK: - Machines

    /// Registers a machine against a license.
    ///
    /// No policy limit is checked here -- limits surface later, through
    /// validation. Prefer `activateMachine` when the desired behaviour is
    /// "reject an over-limit activation".
    public func createMachine(_ options: CreateMachineOptions) async throws -> Machine {
        let data = try await transport.postJSON(["machines"], body: options.requestBody)
        return Machine.fromResource(
            try Self.decode(DataEnvelope<MachineAttributes>.self, from: data).data)
    }

    /// Deletes a machine, freeing its seat.
    public func deleteMachine(_ machineId: String) async throws {
        try await transport.delete(["machines", machineId])
    }

    /// Registers a machine and validates the license in one step, rolling the
    /// machine back if the license turns out to be over a policy limit.
    ///
    /// This is a composite, not a single endpoint: create, then validate, then
    /// delete on an over-limit verdict. Machine creation itself enforces
    /// nothing, so without the rollback an over-limit activation would leave a
    /// row behind that still consumes a seat.
    ///
    /// - Throws: `TamgaError.machineOverLimit` if validation reported an
    ///   over-limit code. The machine has already been deleted by then; the
    ///   meta says which limit was exceeded.
    public func activateMachine(
        _ options: CreateMachineOptions,
        scope: Scope? = nil
    ) async throws -> ActivationResult {
        let machine = try await createMachine(options)
        let validation: ValidationResult
        do {
            validation = try await validateById(options.licenseId,
                                                options: ValidateOptions(scope: scope))
        } catch {
            // Validation failed outright, so whether the machine is permitted
            // is unknown. Roll it back rather than leak a seat whose id the
            // caller never received, and let the original failure propagate.
            await deleteIgnoringFailure(machine.id)
            throw error
        }

        if validation.meta.code.isOverLimit {
            await deleteIgnoringFailure(machine.id)
            throw TamgaError.machineOverLimit(validation.meta)
        }
        return ActivationResult(machine: machine, meta: validation.meta)
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
    /// The server's heartbeat window is a hardcoded 600 seconds regardless of
    /// the policy's `heartbeat_duration`. Use `HeartbeatScheduler` rather than
    /// driving this by hand.
    public func pingHeartbeat(machineId: String) async throws -> Machine {
        let data = try await transport.postJSON(
            ["machines", machineId, "actions", "ping-heartbeat"], body: nil)
        return Machine.fromResource(
            try Self.decode(DataEnvelope<MachineAttributes>.self, from: data).data)
    }

    /// Resets a machine's heartbeat, returning it to the not-started state.
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
    /// The process window is a hardcoded 30 seconds with no resurrection grace:
    /// a dead process row is deleted outright. Use `ProcessHeartbeatScheduler`
    /// rather than driving this by hand.
    public func pingProcess(processId: String) async throws -> MachineProcess {
        let data = try await transport.postJSON(
            ["processes", processId, "actions", "ping"], body: nil)
        return MachineProcess.fromResource(
            try Self.decode(DataEnvelope<ProcessAttributes>.self, from: data).data)
    }
}
