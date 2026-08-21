import Foundation

/// Pings a machine's heartbeat on a timer.
///
/// The server's heartbeat window is the policy's `heartbeat_duration`, falling
/// back to **600 seconds** only when that field is null.
///
/// **This scheduler assumes the fallback.** `window` is the 600s fallback and
/// `defaultInterval` is a third of it, which tolerates two consecutive failed
/// pings only on a policy that takes the fallback. Nothing here reads the
/// policy -- the SDK exposes no `getPolicy`/`getMachine` to read it with -- so
/// on a policy with a shorter window the default rate is too slow and the
/// machine will report `.dead`. Such a caller must pass an explicit `interval`
/// under a third of its own window -- a window this SDK cannot report, since it
/// exposes no `getPolicy`/`getMachine`.
///
/// **A tick never reports `.dead`.** The ping writes `last_heartbeat_at =
/// NOW()` and then derives the status from that same timestamp, so this route
/// answers `.alive` or `.resurrected` and nothing else. A `.dead` branch in a
/// tick callback is unreachable code. The status is real, just not reachable
/// from here: it is served from a machine *read*, which this SDK sees only
/// through the offline machine file `checkOutMachine` issues.
///
/// **So the rule is positive: the loop stops for no status at all** --
/// not `.dead`, not one this SDK does not recognize. Were a late status to
/// surface, it would mean only that the last ping is older than the window,
/// never that the row was culled: culling is gated on the policy's
/// `require_heartbeat`, which defaults to `false`, and the status never
/// consults that flag. The row and its seat stay in place, and the next ping
/// revives the machine -- the write is a bare `last_heartbeat_at = NOW()` with
/// no resurrection check.
///
/// The one terminal signal a ping can give is a `404` -- the row is gone, and
/// only a fresh activation brings it back. That is what `TamgaError.isNotFound`
/// is for, and what re-activation should hang off.
///
/// ```swift
/// let scheduler = HeartbeatScheduler(client: client, machineId: machine.id) { machine, error in
///     // No status branch: a ping answers .alive or .resurrected, and the loop
///     // keeps running whatever a tick carries.
///     // A 404 is the one thing that is terminal -- the row is gone.
///     if let error = error as? TamgaError, error.isNotFound { await reactivate() }
/// }
/// await scheduler.start()
/// ```
///
/// **Handle the tick callback.** It is the only way to observe a ping failing,
/// and errors are reported rather than swallowed for that reason.
public actor HeartbeatScheduler {
    /// The server's **fallback** machine heartbeat window, applied when the
    /// policy leaves `heartbeat_duration` null. A policy that sets that field
    /// overrides this, and nothing here observes the override.
    public static let window: TimeInterval = 600

    /// A third of `window`, leaving room for two consecutive failures -- on a
    /// policy that takes the 600s fallback. See the type's note for the rest.
    public static let defaultInterval: TimeInterval = window / 3

    private let client: TamgaClient
    private let machineId: String
    private let interval: TimeInterval
    private let onTick: @Sendable (Machine?, (any Error)?) async -> Void
    private var task: Task<Void, Never>?

    /// Creates a scheduler. It does not start until `start()` is called.
    ///
    /// A non-positive `interval` falls back to `defaultInterval`.
    public init(
        client: TamgaClient,
        machineId: String,
        interval: TimeInterval = HeartbeatScheduler.defaultInterval,
        onTick: @escaping @Sendable (Machine?, (any Error)?) async -> Void = { _, _ in }
    ) {
        self.client = client
        self.machineId = machineId
        self.interval = interval > 0 ? interval : Self.defaultInterval
        self.onTick = onTick
    }

    /// Whether the scheduler is currently running.
    public var isRunning: Bool { task != nil }

    /// Starts pinging. The first ping fires after one interval, not
    /// immediately -- a machine has just been activated when a scheduler is
    /// created, so its heartbeat is already fresh.
    ///
    /// Calling this on an already-running scheduler does nothing.
    ///
    /// **The loop is unconditional and deliberately so.** No status ends it
    /// and neither does a tick that throws. A ping cannot even answer `.dead`
    /// -- it writes `last_heartbeat_at` before judging the machine by it -- and
    /// a machine that did read late is revived by the very next ping, so
    /// stopping would strand one the server would have brought back on its own.
    /// Only `stop()` and cancellation end it.
    public func start() {
        guard task == nil else { return }
        let interval = self.interval
        task = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                } catch {
                    return
                }
                guard let self else { return }
                // No status check here on purpose -- see start()'s note. The
                // outcome goes to the caller's tick callback and the loop
                // continues regardless of what it was.
                await self.tick()
            }
        }
    }

    /// Stops pinging. Safe to call more than once.
    ///
    /// A ping already in flight is allowed to finish, so one final tick
    /// callback may arrive after this returns. Nothing further is scheduled.
    public func stop() {
        task?.cancel()
        task = nil
    }

    /// Sends one ping and reports the outcome. Exposed so tests can drive a
    /// single tick without waiting on a timer.
    func tick() async {
        do {
            let machine = try await client.pingHeartbeat(machineId: machineId)
            await onTick(machine, nil)
        } catch {
            await onTick(nil, error)
        }
    }
}

/// Pings a process's heartbeat on a timer.
///
/// The process window is a **hardcoded 30 seconds** -- far shorter than even
/// a machine's 600s fallback -- and has no resurrection grace period at all:
/// once a process misses its window the row is deleted outright rather than
/// being marked dead and revivable.
///
/// That makes the tick callback more important here than for machines. A failed
/// ping is much closer to losing the process registration entirely, and the
/// correct recovery is usually to re-create the process rather than keep
/// pinging a row that no longer exists.
public actor ProcessHeartbeatScheduler {
    /// The server's hardcoded process heartbeat window.
    public static let window: TimeInterval = 30

    /// A third of `window`, leaving room for two consecutive failures.
    public static let defaultInterval: TimeInterval = window / 3

    private let client: TamgaClient
    private let processId: String
    private let interval: TimeInterval
    private let onTick: @Sendable (MachineProcess?, (any Error)?) async -> Void
    private var task: Task<Void, Never>?

    /// Creates a scheduler. It does not start until `start()` is called.
    public init(
        client: TamgaClient,
        processId: String,
        interval: TimeInterval = ProcessHeartbeatScheduler.defaultInterval,
        onTick: @escaping @Sendable (MachineProcess?, (any Error)?) async -> Void = { _, _ in }
    ) {
        self.client = client
        self.processId = processId
        self.interval = interval > 0 ? interval : Self.defaultInterval
        self.onTick = onTick
    }

    /// Whether the scheduler is currently running.
    public var isRunning: Bool { task != nil }

    /// Starts pinging, with the first ping one interval from now.
    public func start() {
        guard task == nil else { return }
        let interval = self.interval
        task = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                } catch {
                    return
                }
                guard let self else { return }
                await self.tick()
            }
        }
    }

    /// Stops pinging. Safe to call more than once.
    ///
    /// A ping already in flight is allowed to finish, so one final tick
    /// callback may arrive after this returns. Nothing further is scheduled.
    public func stop() {
        task?.cancel()
        task = nil
    }

    /// Sends one ping and reports the outcome.
    func tick() async {
        do {
            let process = try await client.pingProcess(processId: processId)
            await onTick(process, nil)
        } catch {
            await onTick(nil, error)
        }
    }
}
