import Foundation
import Testing

@testable import Tamga

@Suite("Heartbeat scheduling")
struct SchedulerTests {
    /// Collects tick outcomes across tasks.
    private actor TickLog {
        private(set) var machines: [Machine?] = []
        private(set) var errors: [(any Error)?] = []

        func record(_ machine: Machine?, _ error: (any Error)?) {
            machines.append(machine)
            errors.append(error)
        }

        var count: Int { machines.count }
        var errorCount: Int { errors.compactMap { $0 }.count }

        func machineCount(nonNil: Bool) -> Int {
            nonNil ? machines.compactMap { $0 }.count : machines.count
        }

        func statuses(prefix count: Int) -> [HeartbeatStatus?] {
            machines.prefix(count).map { $0?.heartbeatStatus }
        }

        /// Whether the first recorded error is the server's row-is-gone `404`.
        ///
        /// Reduced to a `Bool` in here rather than handing `[(any Error)?]` out
        /// across the actor boundary, which is not `Sendable`.
        var firstErrorIsNotFound: Bool {
            guard let error = errors.compactMap({ $0 }).first else { return false }
            return (error as? TamgaError)?.isNotFound == true
        }
    }

    @Test("the default interval is a third of the server window")
    func defaultIntervalIsAThirdOfServerWindow() {
        #expect(HeartbeatScheduler.window == 600)
        #expect(HeartbeatScheduler.defaultInterval == 200)
        #expect(ProcessHeartbeatScheduler.window == 30)
        #expect(ProcessHeartbeatScheduler.defaultInterval == 10)
    }

    @Test("a tick reports the updated machine")
    func tickReportsUpdatedMachine() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        let log = TickLog()
        let scheduler = HeartbeatScheduler(
            client: TamgaClient.mocked(performer), machineId: "mach-1"
        ) { machine, error in
            await log.record(machine, error)
        }

        await scheduler.tick()

        #expect(await log.machines.first??.heartbeatStatus == .alive)
        #expect(await log.errorCount == 0)
    }

    @Test("a tick surfaces the dead status rather than hiding it")
    func tickSurfacesDeadStatus() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"mach-1","type":"machines","attributes":{"heartbeat_status":"DEAD"}}}
        """)
        let log = TickLog()
        let scheduler = HeartbeatScheduler(
            client: TamgaClient.mocked(performer), machineId: "mach-1"
        ) { machine, error in
            await log.record(machine, error)
        }

        await scheduler.tick()

        // DEAD says only that the last ping is older than the window -- the
        // row and its seat are still there. It is surfaced, not acted on.
        #expect(await log.machines.first??.heartbeatStatus == .dead)
    }

    @Test("the loop keeps pinging across three consecutive dead responses")
    func loopKeepsPingingAcrossThreeConsecutiveDeadResponses() async throws {
        // Regression: a scheduler that treats DEAD as "the row was culled" and
        // stops strands a machine the server would have revived. Nothing is
        // culled at all under a default policy (require_heartbeat = FALSE), the
        // status is computed from last_heartbeat_at alone, and the ping is an
        // unconditional last_heartbeat_at = NOW() that brings the machine back.
        // Only a 404 from the ping means the row is gone.
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"mach-1","type":"machines","attributes":{"heartbeat_status":"DEAD"}}}
        """)
        let log = TickLog()
        let scheduler = HeartbeatScheduler(
            client: TamgaClient.mocked(performer), machineId: "mach-1", interval: 0.02
        ) { machine, error in
            await log.record(machine, error)
        }

        await scheduler.start()

        var observed = 0
        for _ in 0..<200 where observed < 3 {
            try await Task.sleep(nanoseconds: 20_000_000)
            observed = await log.count
        }
        await scheduler.stop()

        #expect(observed >= 3)
        #expect(await log.statuses(prefix: 3) == [.dead, .dead, .dead])
        #expect(await log.errorCount == 0)
        #expect(await performer.requestCount >= 3)
    }

    @Test("a 404 from the ping, not the dead status, is the row-is-gone signal")
    func notFoundFromThePingIsTheRowIsGoneSignal() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 404, body: "{\"errors\":[{\"code\":\"NOT_FOUND\"}]}")
        let log = TickLog()
        let scheduler = HeartbeatScheduler(
            client: TamgaClient.mocked(performer), machineId: "mach-1"
        ) { machine, error in
            await log.record(machine, error)
        }

        await scheduler.tick()

        #expect(await log.firstErrorIsNotFound)
    }

    @Test("a failed ping is reported rather than swallowed")
    func failedPingIsReportedRatherThanSwallowed() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 404, body: "{\"errors\":[{\"code\":\"NOT_FOUND\"}]}")
        let log = TickLog()
        let scheduler = HeartbeatScheduler(
            client: TamgaClient.mocked(performer), machineId: "mach-1"
        ) { machine, error in
            await log.record(machine, error)
        }

        await scheduler.tick()

        #expect(await log.machineCount(nonNil: true) == 0)
        #expect(await log.errorCount == 1)
    }

    @Test("a scheduler runs until stopped")
    func schedulerRunsUntilStopped() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        let log = TickLog()
        let scheduler = HeartbeatScheduler(
            client: TamgaClient.mocked(performer), machineId: "mach-1", interval: 0.02
        ) { machine, error in
            await log.record(machine, error)
        }

        await scheduler.start()
        #expect(await scheduler.isRunning)

        // Wait for a couple of ticks without asserting on exact timing.
        var observed = 0
        for _ in 0..<200 where observed < 2 {
            try await Task.sleep(nanoseconds: 20_000_000)
            observed = await log.count
        }
        #expect(observed >= 2)

        await scheduler.stop()
        #expect(await scheduler.isRunning == false)

        // A ping already in flight when stop() lands is allowed to finish, so
        // drain first, then assert the count has genuinely stopped growing.
        try await Task.sleep(nanoseconds: 120_000_000)
        let settled = await log.count
        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(await log.count == settled)
    }

    @Test("starting twice does not create a second timer")
    func startingTwiceDoesNotCreateSecondTimer() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        let scheduler = HeartbeatScheduler(
            client: TamgaClient.mocked(performer), machineId: "mach-1", interval: 30)

        await scheduler.start()
        await scheduler.start()
        #expect(await scheduler.isRunning)

        await scheduler.stop()
        await scheduler.stop()
        #expect(await scheduler.isRunning == false)
    }

    @Test("a non-positive interval falls back to the default")
    func nonPositiveIntervalFallsBackToDefault() async {
        let performer = MockPerformer()
        let client = TamgaClient.mocked(performer)
        let zero = HeartbeatScheduler(client: client, machineId: "m", interval: 0)
        let negative = ProcessHeartbeatScheduler(client: client, processId: "p", interval: -5)

        #expect(await zero.isRunning == false)
        #expect(await negative.isRunning == false)
    }

    @Test("a process scheduler tick reports the process")
    func processSchedulerTickReportsProcess() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"proc-1","type":"processes","attributes":{"pid":"77",\
        "machine_id":"mach-1"}}}
        """)
        let received = ProcessLog()
        let scheduler = ProcessHeartbeatScheduler(
            client: TamgaClient.mocked(performer), processId: "proc-1"
        ) { process, _ in
            await received.record(process?.pid)
        }

        await scheduler.tick()

        #expect(await received.pids == ["77"])
    }

    private actor ProcessLog {
        private(set) var pids: [String?] = []

        func record(_ pid: String?) {
            pids.append(pid)
        }
    }
}
