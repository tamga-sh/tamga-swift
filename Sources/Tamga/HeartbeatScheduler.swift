import Foundation

/// Pings a machine's heartbeat on a timer.
///
/// The server's heartbeat window is the policy's `heartbeat_duration`, falling
/// back to **600 seconds** only when that field is null.
///
/// **The default interval assumes the fallback; ask for the policy's real
/// window instead.** `window` is the 600s fallback and `defaultInterval` is a
/// third of it, which leaves room for two consecutive failed pings only on a
/// policy that takes the fallback. On a policy with a shorter window that rate
/// is too slow, the machine falls outside its window, and under a policy that
/// requires heartbeats its row is culled.
///
/// `sizedToPolicy(client:machineId:licenseId:onTick:)` reads the window off the
/// licence's policy and sizes the interval from that. It costs one extra
/// request at startup and is the correct default for anyone who does not
/// already know their own policy:
///
/// ```swift
/// let scheduler = try await HeartbeatScheduler.sizedToPolicy(
///     client: client, machineId: machine.id, licenseId: licenseId)
/// await scheduler.start()
/// ```
///
/// Do **not** try to recover the window from `Machine.nextHeartbeatAt`. Which
/// endpoint produced the machine decides what that field means: `createMachine`,
/// `pingHeartbeat`, `resetHeartbeat` and `updateMachine` compute it against the
/// 600s fallback, while `getMachine`, `listMachines`, `checkOutMachine` and
/// `generateOfflineProof` compute it against the policy. Two responses for the
/// same machine seconds apart can disagree, and the endpoint a scheduler
/// naturally calls is the one that is wrong.
///
/// **A tick never reports `.dead`.** The ping writes `last_heartbeat_at =
/// NOW()` and then derives the status from that same timestamp, so this route
/// answers `.alive` or `.resurrected` and nothing else. A `.dead` branch in a
/// tick callback is unreachable code. The status is real and is readable
/// elsewhere -- `getMachine(_:)`, `listMachines`, `checkOutMachine`,
/// `generateOfflineProof`, and even `updateMachine`, which is a write that
/// never touches the heartbeat column. It is just not something a ping can
/// say.
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
    /// policy leaves `heartbeat_duration` null.
    ///
    /// A policy that sets that field overrides this. `sizedToPolicy` observes
    /// the override; the plain initializer does not.
    public static let window: TimeInterval = 600

    /// A third of `window`, leaving room for two consecutive failures -- on a
    /// policy that takes the 600s fallback. See the type's note for the rest.
    public static let defaultInterval: TimeInterval = window / 3

    /// The shortest interval either scheduler will actually run at: a bound on
    /// the request rate, not a rounding convenience -- see
    /// `flooredInterval(_:)`. `ProcessHeartbeatScheduler` shares this rather
    /// than restating it, so the number has one definition.
    static let minimumInterval: TimeInterval = 1

    /// Confines an interval to one that cannot flood the licensing server.
    ///
    /// **Measured, not assumed.** `start()` sleeps
    /// `UInt64(interval * 1_000_000_000)` nanoseconds, and `Task.sleep` honours
    /// a sub-second delay *exactly*: on Swift 6.3 / macOS 26, `0.5` sleeps a
    /// mean 531 ms and `0.001` a mean 1.5 ms -- about 665 pings a second, each
    /// individually valid and correctly authenticated, from every machine
    /// running that code. An interval of `0` does not sleep at all and turns
    /// the loop over ~285,000 times a second. So a guard on only the
    /// non-positive case bounds nothing: it rejects `0` and passes `0.001`,
    /// which is the more damaging of the two in any process that survives its
    /// first request. Only a floor bounds the rate.
    ///
    /// It costs nothing a policy can express -- `heartbeat_duration` is an
    /// integer-**seconds** column; `interval(forWindowSeconds:)` has that
    /// arithmetic and the window cases this does not cover.
    ///
    /// A negative or `.nan` interval also becomes the floor, which keeps it
    /// away from `UInt64(_:)` -- that conversion traps (`SIGILL`) on a
    /// negative, on `.nan` and on `.infinity` alike. The floor does not save
    /// `.infinity`, since `max` propagates it, but nor did the guard it
    /// replaces.
    static func flooredInterval(_ interval: TimeInterval) -> TimeInterval {
        // max(1, .nan) is 1: Swift's max returns `y >= x ? y : x` and every
        // comparison against .nan is false. Verified, not assumed -- the
        // ternary this replaced relied on the same property.
        max(minimumInterval, interval)
    }

    /// The ping interval for a heartbeat window of `seconds`: a third of it,
    /// floored at `minimumInterval`, with a non-positive window taking the
    /// server's own 600s fallback before the division rather than after it.
    ///
    /// The third tolerates two consecutive failed pings before the window
    /// lapses. The floor stops a *short* window becoming a spin; the window
    /// fallback stops a *nonsensical* one becoming an expensive one --
    /// `heartbeat_duration` is an `INTEGER` with no `CHECK` constraint, so `0`
    /// and negatives really are storable, and `windowSeconds(for:)` reports
    /// them verbatim by design.
    ///
    /// **Why the two are not the same guard.** A window of `0` cannot be held
    /// at *any* ping rate: `effective_window_secs()` is
    /// `policy_heartbeat_duration.map(i64::from).unwrap_or(600)`, replacing
    /// `NULL` only, so a stored `0` is judged as zero-length and the machine
    /// reads `DEAD` whatever this returns. Dividing the raw `0` and letting the
    /// floor catch the result would ping once a second, forever, from every
    /// machine that policy licenses, to achieve nothing -- the same
    /// self-inflicted denial of service the floor exists to prevent, reached
    /// from the other side. Taking the fallback window first reaches the
    /// identical verdict at 200s: 200x fewer requests. So the floor governs
    /// every window a policy can *usefully* state, the fallback governs the
    /// ones it cannot state at all, and a caller-supplied interval keeps the
    /// plain floor.
    ///
    /// **What the floor costs, which is not what it looks like.** The server's
    /// rule is *not* "dead once age passes the window".
    /// `heartbeat_status_within` computes
    /// `let age_secs = (Utc::now() - hb_ts).num_seconds()` then
    /// `age_secs <= window_secs`, and chrono's `num_seconds()` truncates
    /// (`Duration::milliseconds(1999).num_seconds() == 1`, verified against the
    /// API's own chrono 0.4.45). A machine therefore first reads `DEAD` at an
    /// age of `window_secs + 1` seconds: every window carries one free second,
    /// and a 1s window pinged every 1s has two seconds of slack, not zero.
    ///
    /// What degrades is the divisor's promise of two tolerable consecutive
    /// losses. Window 3 is where floor and divisor first agree; 2 keeps one
    /// spare ping, 1 keeps none, and steady state holds the window in all
    /// three. The window *no* interval can hold is **`0`**, whose entire grace
    /// *is* that free second -- not `1`, the intuitive but wrong answer. A
    /// negative window is unholdable too (`age_secs <= -30` is false for every
    /// age), and neither reaches the floor: both take the fallback window
    /// above. Pinned as a table in `HeartbeatFloorTests`.
    public static func interval(forWindowSeconds seconds: Int) -> TimeInterval {
        let effective = seconds > 0 ? TimeInterval(seconds) : window
        return flooredInterval(effective / 3)
    }

    /// The heartbeat window a policy actually imposes, in seconds.
    ///
    /// `policy.heartbeatDuration` when it is set, and the server's own 600s
    /// fallback when it is `nil` -- mirroring
    /// `Policy::effective_heartbeat_duration_secs` server-side, which is also
    /// what the cull job's `COALESCE(p.heartbeat_duration, 600)` uses.
    ///
    /// The mirroring is exact, which means a stored non-positive duration is
    /// returned as-is rather than being nudged to 600. The server does not
    /// substitute the fallback for a zero either, and a function documented as
    /// reporting what the server thinks the window is should not quietly report
    /// something else. `interval(forWindowSeconds:)` is where a short window is
    /// made safe, by flooring the interval it derives, and where a non-positive
    /// one is -- by substituting the fallback window for its own division only.
    /// Neither changes the number reported here.
    public static func windowSeconds(for policy: Policy) -> Int {
        policy.heartbeatDuration ?? Int(window)
    }

    /// Builds a scheduler whose interval is sized to the licence's policy
    /// rather than to the 600s fallback.
    ///
    /// Reads the policy once, at construction, with `getLicensePolicy`. It is
    /// not re-read: a policy change mid-run is not observed, so a long-lived
    /// process that expects its policy to be retuned should rebuild the
    /// scheduler rather than assume this tracks it.
    ///
    /// - Throws: whatever `getLicensePolicy` throws. Reading the policy needs
    ///   the `license.read` permission; a credential without it gets a `403`
    ///   here, and the fallback-sized initializer is the way through that.
    public static func sizedToPolicy(
        client: TamgaClient,
        machineId: String,
        licenseId: String,
        onTick: @escaping @Sendable (Machine?, (any Error)?) async -> Void = { _, _ in }
    ) async throws -> HeartbeatScheduler {
        let policy = try await client.getLicensePolicy(licenseId)
        return HeartbeatScheduler(
            client: client,
            machineId: machineId,
            interval: interval(forWindowSeconds: windowSeconds(for: policy)),
            onTick: onTick)
    }

    private let client: TamgaClient
    private let machineId: String
    private let interval: TimeInterval
    private let onTick: @Sendable (Machine?, (any Error)?) async -> Void
    private var task: Task<Void, Never>?

    /// Creates a scheduler. It does not start until `start()` is called.
    ///
    /// **`interval` is floored at one second**, not merely guarded against
    /// non-positive values: `0.5` becomes `1`, and so do `0`, `-5` and `.nan`.
    /// Nothing throws. See `flooredInterval(_:)` for why. To ask for the
    /// default, omit the parameter -- passing `0` no longer means "use 200s",
    /// it means one second. A window-derived interval is the other case, and
    /// `interval(forWindowSeconds:)` owns it.
    public init(
        client: TamgaClient,
        machineId: String,
        interval: TimeInterval = HeartbeatScheduler.defaultInterval,
        onTick: @escaping @Sendable (Machine?, (any Error)?) async -> Void = { _, _ in }
    ) {
        self.client = client
        self.machineId = machineId
        self.interval = Self.flooredInterval(interval)
        self.onTick = onTick
    }

    /// Whether the scheduler is currently running.
    public var isRunning: Bool { task != nil }

    /// The interval this scheduler actually settled on. Internal: exposed so a
    /// test can assert that `sizedToPolicy` read the window rather than
    /// silently falling back.
    var configuredInterval: TimeInterval { interval }

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
    ///
    /// **`interval` takes the same one-second floor** as `HeartbeatScheduler`,
    /// for the same reason: this is the identical unguarded `Task.sleep` one
    /// type away, so an explicit `0` -- or a `.nan` out of caller-side
    /// arithmetic -- spins `POST /processes/{id}/actions/ping` exactly as hard.
    /// The 30s window is hardcoded server-side, so the floor is still thirty
    /// pings inside it and costs nothing here.
    public init(
        client: TamgaClient,
        processId: String,
        interval: TimeInterval = ProcessHeartbeatScheduler.defaultInterval,
        onTick: @escaping @Sendable (MachineProcess?, (any Error)?) async -> Void = { _, _ in }
    ) {
        self.client = client
        self.processId = processId
        self.interval = HeartbeatScheduler.flooredInterval(interval)
        self.onTick = onTick
    }

    /// Whether the scheduler is currently running.
    public var isRunning: Bool { task != nil }

    /// The interval this scheduler settled on. Internal: exposed so a test can
    /// assert the floor bound rather than infer it from timing.
    var configuredInterval: TimeInterval { interval }

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

    /// Stops pinging and deletes the process registration.
    ///
    /// **This is the shutdown path, and skipping it leaks a row permanently.**
    /// The server's process reaper does not run, so a registration nothing
    /// deletes survives its own process, its own machine's next boot, and every
    /// boot after that. Processes count against `policy.maxProcesses`, so the
    /// accumulation eventually fails a validation with `TOO_MANY_PROCESSES`
    /// long after the application that caused it stopped running.
    ///
    /// Pinging stops first, so a tick cannot race the delete and re-create
    /// nothing -- a ping against a deleted row is a `404`, not a resurrection.
    ///
    /// - Throws: whatever `deleteProcess` throws. A `404`
    ///   (`TamgaError.isNotFound`) means the row was already gone, which on a
    ///   shutdown path is usually not worth surfacing.
    public func stopAndDelete() async throws {
        stop()
        try await client.deleteProcess(processId)
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
