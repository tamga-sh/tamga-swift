import Foundation
import Testing

@testable import Tamga

/// `Entitlement.kind`/`maxValue`/`currentValue` and the three meter actions
/// (`incrementEntitlementUsage`/`decrementEntitlementUsage`/
/// `resetEntitlementUsage`) added by the entitlement metering migration --
/// split out of `EntitlementTests` to keep that file under the line-length
/// gate.
@Suite("Entitlement metering")
struct EntitlementMeteringTests {
    // MARK: - kind, maxValue, currentValue

    @Test("kind decodes flag and meter, and falls back to unknown for anything else")
    func kindDecodesFlagAndMeter() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":[{"id":"ent-1","type":"entitlements","attributes":{"code":"PRO","kind":"flag"}},\
        {"id":"ent-2","type":"entitlements","attributes":{"code":"REQUESTS","kind":"meter"}},\
        {"id":"ent-3","type":"entitlements","attributes":{"code":"FUTURE","kind":"widget"}}]}
        """)

        let page = try await TamgaClient.mocked(performer).listEntitlements(licenseId: "lic-1")

        #expect(page.items[0].kind == .flag)
        #expect(page.items[1].kind == .meter)
        #expect(page.items[2].kind == .unknown("widget"))
    }

    @Test("kind falls back to unknown when the server omits it")
    func kindFallsBackToUnknownWhenOmitted() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-1","type":"entitlements","attributes":{"code":"PRO"}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).getEntitlement(
            licenseId: "lic-1", entitlementId: "ent-1")

        #expect(entitlement.kind == .unknown(""))
    }

    @Test("maxValue and currentValue are carried through on a license-scoped meter")
    func maxValueAndCurrentValueAreCarriedThrough() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-2","type":"entitlements","attributes":{"code":"REQUESTS",\
        "kind":"meter","inherited":false,"max_value":1000,"current_value":650}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).getEntitlement(
            licenseId: "lic-1", entitlementId: "ent-2")

        #expect(entitlement.maxValue == 1000)
        #expect(entitlement.currentValue == 650)
    }

    @Test("maxValue and currentValue are nil where the server does not emit them")
    func maxValueAndCurrentValueAreAbsentWhereNotEmitted() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-1","type":"entitlements","attributes":{"code":"PRO","kind":"flag"}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).getEntitlement(
            licenseId: "lic-1", entitlementId: "ent-1")

        #expect(entitlement.maxValue == nil)
        #expect(entitlement.currentValue == nil)
    }

    @Test("a null max_value means unlimited, not zero")
    func nullMaxValueMeansUnlimited() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-2","type":"entitlements","attributes":{"code":"REQUESTS",\
        "kind":"meter","max_value":null,"current_value":12}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).getEntitlement(
            licenseId: "lic-1", entitlementId: "ent-2")

        #expect(entitlement.maxValue == nil)
        #expect(entitlement.currentValue == 12)
    }

    // MARK: - Meter actions

    @Test("incrementEntitlementUsage posts to its own action and returns the fresh counter")
    func incrementEntitlementUsageHitsItsOwnAction() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-2","type":"entitlements","attributes":{"code":"REQUESTS",\
        "kind":"meter","max_value":1000,"current_value":651}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).incrementEntitlementUsage(
            licenseId: "lic-1", entitlementId: "ent-2")

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/entitlements/ent-2/actions/increment")
        #expect(await performer.requestBody(at: 0) == "")
        #expect(entitlement.currentValue == 651)
    }

    @Test("incrementEntitlementUsage sends an explicit increment in the body")
    func incrementEntitlementUsageSendsExplicitIncrement() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-2","type":"entitlements","attributes":{"code":"REQUESTS",\
        "kind":"meter","max_value":1000,"current_value":655}}}
        """)

        _ = try await TamgaClient.mocked(performer).incrementEntitlementUsage(
            licenseId: "lic-1", entitlementId: "ent-2", increment: 5)

        #expect(await performer.requestBody(at: 0) == "{\"increment\":5}")
    }

    @Test("decrementEntitlementUsage posts to its own action")
    func decrementEntitlementUsageHitsItsOwnAction() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-2","type":"entitlements","attributes":{"code":"REQUESTS",\
        "kind":"meter","max_value":1000,"current_value":649}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).decrementEntitlementUsage(
            licenseId: "lic-1", entitlementId: "ent-2", decrement: 1)

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/entitlements/ent-2/actions/decrement")
        #expect(await performer.requestBody(at: 0) == "{\"decrement\":1}")
        #expect(entitlement.currentValue == 649)
    }

    @Test("resetEntitlementUsage posts to its own action with no body")
    func resetEntitlementUsageHitsItsOwnAction() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-2","type":"entitlements","attributes":{"code":"REQUESTS",\
        "kind":"meter","max_value":1000,"current_value":0}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).resetEntitlementUsage(
            licenseId: "lic-1", entitlementId: "ent-2")

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/entitlements/ent-2/actions/reset")
        #expect(await performer.requestBody(at: 0) == "")
        #expect(entitlement.currentValue == 0)
    }

    @Test("incrementEntitlementUsage surfaces METER_LIMIT_EXCEEDED with the entitlement id")
    func incrementEntitlementUsageSurfacesMeterLimitExceeded() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 422, body: """
        {"errors":[{"code":"METER_LIMIT_EXCEEDED","status":"422",\
        "detail":"meter limit exceeded","meta":{"entitlement_id":"ent-2"}}]}
        """)

        do {
            _ = try await TamgaClient.mocked(performer).incrementEntitlementUsage(
                licenseId: "lic-1", entitlementId: "ent-2", increment: 10)
            Issue.record("expected incrementEntitlementUsage to throw")
        } catch let error as TamgaError {
            #expect(error.apiCode == TamgaAPIErrorCode.meterLimitExceeded)
            #expect(error.isMeterLimitExceeded == true)
            #expect(error.meterLimitEntitlementId == "ent-2")
        }
    }
}
