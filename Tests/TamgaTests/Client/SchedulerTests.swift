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

        // DEAD means the row was culled server-side: the caller must
        // re-activate, not keep pinging.
        #expect(await log.machines.first??.heartbeatStatus == .dead)
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
