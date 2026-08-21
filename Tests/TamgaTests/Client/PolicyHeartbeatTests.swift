import Foundation
import Testing

@testable import Tamga

@Suite("Policy-sized heartbeat interval")
struct PolicyHeartbeatIntervalTests {
    @Test("the interval is a third of the window")
    func intervalIsAThirdOfTheWindow() {
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 90) == 30)
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 600)
            == HeartbeatScheduler.defaultInterval)
    }

    @Test("a short window takes the floor; a non-positive one takes the fallback window")
    func shortWindowTakesTheFloorAndNonPositiveTakesTheFallback() {
        // Changed 2026-08-21. A window of 1 or 2 used to divide to a 333ms or
        // 667ms ping -- the old guard was on the non-positive case only, so it
        // bounded nothing above zero. The floor bounds the rate instead.
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 1) == 1)
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 2) == 1)

        // The floor binds only where the third is shorter than it: a window
        // the divisor can serve is untouched.
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 3) == 1)
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 6) == 2)

        // A non-positive window is a different case and keeps its old answer.
        // It cannot be held at any rate, so the cheapest schedule that reaches
        // the same verdict is the right one -- 200s rather than the 1s the
        // floor alone would give, which is 200x fewer pointless requests.
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 0)
            == HeartbeatScheduler.defaultInterval)
        #expect(HeartbeatScheduler.interval(forWindowSeconds: -1)
            == HeartbeatScheduler.defaultInterval)
    }

    @Test("a policy with no heartbeat duration takes the server's 600s fallback")
    func nullHeartbeatDurationTakesTheFallback() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"pol-2","type":"policies","attributes":{"name":"Default"}}}
        """)

        let policy = try await TamgaClient.mocked(performer).getLicensePolicy("lic-1")

        #expect(policy.heartbeatDuration == nil)
        #expect(HeartbeatScheduler.windowSeconds(for: policy) == 600)
    }

    @Test("a zero duration is reported as-is, and made safe by the interval")
    func zeroDurationIsReportedNotNudged() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"pol-3","type":"policies","attributes":{"heartbeat_duration":0}}}
        """)

        let policy = try await TamgaClient.mocked(performer).getLicensePolicy("lic-1")

        // The server does not substitute 600 for a zero, so neither does this --
        // reporting the window and making it safe are different jobs. The
        // second job is the interval's, which takes the fallback *window*
        // before dividing rather than reporting a different one here.
        #expect(HeartbeatScheduler.windowSeconds(for: policy) == 0)
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 0)
            == HeartbeatScheduler.defaultInterval)
    }

    @Test("sizedToPolicy reads the policy and sizes the interval from it")
    func sizedToPolicyReadsThePolicy() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.policy)

        let scheduler = try await HeartbeatScheduler.sizedToPolicy(
            client: TamgaClient.mocked(performer), machineId: "mach-1", licenseId: "lic-1")

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/policy")
        // 90s window -> 30s interval, not the 200s the 600s fallback would give.
        #expect(await scheduler.configuredInterval == 30)
    }
}

/// The floor and the divisor, in one place, against the server's real rule.
///
/// These two numbers do not sit together in the source -- `minimumInterval` is
/// a bound on the request rate, the `/ 3` in `interval(forWindowSeconds:)` is a
/// promise about failure tolerance -- and on a short enough window they
/// interact: the floor binds and the divisor's promise stops holding. This
/// suite names the `heartbeat_duration` value in every case so the interaction
/// is readable rather than re-derived from two places.
///
/// ⚠️ The server's rule is **not** `age > window`. From
/// `tamga-api/src/features/machines/model.rs::heartbeat_status_within`:
///
///     let age_secs = (Utc::now() - hb_ts).num_seconds();
///     let within_window = age_secs <= window_secs;
///
/// and chrono's `num_seconds()` returns *whole* seconds, truncating. Reading it
/// pessimistically -- dead the instant age passes the nominal window -- makes a
/// 1s window look unserveable at a 1s ping when it in fact has a full second of
/// slack, and that misreading is what makes the floor look broken.
@Suite("The interval floor against the server's liveness rule")
struct HeartbeatFloorTests {
    /// One row of the table: a policy window, the interval the SDK derives
    /// from it, and the consecutive pings that can then be lost.
    struct WindowCase: Sendable, CustomStringConvertible {
        let windowSeconds: Int
        let interval: TimeInterval
        let lossesTolerated: Int
        let note: String

        var description: String { "heartbeat_duration \(windowSeconds) (\(note))" }
    }

    /// The first age, in whole seconds, at which a read reports `DEAD`.
    ///
    /// `age_secs <= window_secs` on a truncated `age_secs` means the verdict
    /// flips one whole second later than the nominal window: every window
    /// carries one free second.
    static func deadAtAgeSeconds(_ windowSeconds: Int) -> Int { windowSeconds + 1 }

    /// Consecutive pings that can be lost before a read sees `DEAD`, for a
    /// scheduler ticking every `interval`. After `m` misses the age has reached
    /// `(m + 1) * interval`. `-1` means the window is not held even with no
    /// ping lost at all.
    static func lossesTolerated(windowSeconds: Int, interval: TimeInterval) -> Int {
        Int((Double(deadAtAgeSeconds(windowSeconds)) / interval).rounded(.up)) - 2
    }

    @Test("truncation gives every window a free second, which is what makes 1s serveable")
    func truncationGivesEveryWindowAFreeSecond() {
        #expect(Self.deadAtAgeSeconds(0) == 1)
        #expect(Self.deadAtAgeSeconds(1) == 2)
        #expect(Self.deadAtAgeSeconds(2) == 3)
        #expect(Self.deadAtAgeSeconds(600) == 601)

        // The pessimistic reading would put a 1s window's deadline at 1s and
        // make the 1s floor an exact boundary case. It is 2s, so the floor has
        // 2x margin on the shortest window a policy can actually express.
        #expect(Self.deadAtAgeSeconds(1) > 1)

        // ⚠️ STANDING CAVEAT -- this is the assertion that breaks first.
        //
        // Everything in this suite, and the fleet-wide decision to floor the
        // ping interval at one second, rests on `num_seconds()` truncating.
        // Verified against the API's own chrono 0.4.45:
        // `Duration::milliseconds(1999).num_seconds() == 1`, and a window of 1
        // first reads DEAD at an age of 2000ms rather than 1001ms.
        //
        // If the server ever compares sub-second -- a chrono bump that changes
        // the semantics, or a rewrite to `num_milliseconds()` -- this line is
        // where it surfaces, and the table below inverts with it. Window `1`
        // would become the genuine boundary case it is often assumed to be
        // already: DEAD at exactly 1000ms, pinged every 1000ms, held by
        // nothing. Window `0` would be unserveable at any rate rather than
        // merely at every rate this SDK will run at, which is the only reason
        // the two currently share an answer. Do not "fix" this test by
        // relaxing it; the floor itself is what would need revisiting.
    }

    @Test(
        "each heartbeat_duration, the interval it produces, and the losses it tolerates",
        arguments: [
            WindowCase(windowSeconds: 600, interval: 200, lossesTolerated: 2,
                       note: "the 600s fallback: the divisor governs, the floor is irrelevant"),
            WindowCase(windowSeconds: 3, interval: 1, lossesTolerated: 2,
                       note: "the first window where floor and divisor agree exactly"),
            WindowCase(windowSeconds: 2, interval: 1, lossesTolerated: 1,
                       note: "the floor binds: the promise degrades from 2 losses to 1"),
            WindowCase(windowSeconds: 1, interval: 1, lossesTolerated: 0,
                       note: "the floor binds hardest: steady state holds, no ping to spare"),
            WindowCase(windowSeconds: 0, interval: 200, lossesTolerated: -1,
                       note: "unholdable at any rate, so it takes the fallback window, not the floor")
        ])
    func windowTable(_ row: WindowCase) {
        #expect(HeartbeatScheduler.interval(forWindowSeconds: row.windowSeconds) == row.interval)
        #expect(Self.lossesTolerated(windowSeconds: row.windowSeconds, interval: row.interval)
            == row.lossesTolerated)

        // Steady state -- no ping lost at all -- holds the window in every row
        // but the last, where the free second *is* the entire grace and no
        // interval this SDK will run at fits inside it.
        let holdsSteadyState = row.interval < Double(Self.deadAtAgeSeconds(row.windowSeconds))
        #expect(holdsSteadyState == (row.lossesTolerated >= 0))
    }

    @Test("window 0 is the one no interval can hold, and is deliberately not chased")
    func windowZeroIsNotChased() {
        // A ~333ms ping would in fact hold it: the age never reaches a whole
        // second, so `age_secs <= 0` keeps holding. The SDK does not do that.
        // Chasing it would tie this SDK's request rate to `num_seconds()`
        // truncation -- a server implementation artifact, not a protocol
        // guarantee -- to serve one nonsensical policy value.
        #expect(Self.lossesTolerated(windowSeconds: 0, interval: 1) == -1)
        #expect(Self.lossesTolerated(windowSeconds: 0, interval: 1.0 / 3) >= 0)

        // Since the verdict is DEAD at every rate this SDK will run at, the
        // schedule that reaches it most cheaply wins: the fallback window
        // before the division, not the floor after it.
        #expect(Self.lossesTolerated(windowSeconds: 0, interval: 200) == -1)
        #expect(HeartbeatScheduler.interval(forWindowSeconds: 0)
            == HeartbeatScheduler.defaultInterval)
    }

    @Test("a negative window is unserveable at any rate, so there is nothing to chase")
    func negativeWindowIsUnserveableAtAnyRate() {
        // `age_secs <= -30` is false for every non-negative age, so the row
        // reads DEAD unconditionally. No interval whatsoever serves this
        // policy, so it takes the fallback window like any other non-positive.
        #expect(Self.deadAtAgeSeconds(-30) < 0)
        #expect(HeartbeatScheduler.interval(forWindowSeconds: -30)
            == HeartbeatScheduler.defaultInterval)
    }
}
