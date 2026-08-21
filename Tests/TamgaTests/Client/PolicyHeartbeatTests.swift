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

    @Test("a non-positive window falls back rather than producing a spin")
    func nonPositiveWindowFallsBack() {
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
