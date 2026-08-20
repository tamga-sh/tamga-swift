import Foundation
import Testing

@testable import Tamga

@Suite("Entitlements")
struct EntitlementTests {
    private static let twoEntitlements = """
    {"data":[{"id":"ent-1","type":"entitlements","attributes":{"code":"PRO","name":"Pro plan"}},\
    {"id":"ent-2","type":"entitlements","attributes":{"code":"BETA","name":"Beta"}}]}
    """

    @Test("hasEntitlement matches on the code, not the name")
    func hasEntitlementMatchesOnCodeNotName() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)
        let client = TamgaClient.mocked(performer)

        #expect(try await client.hasEntitlement(licenseId: "lic-1", code: "PRO"))
        // "Pro plan" is a display label; matching on it would break the moment
        // someone renames it.
        #expect(try await client.hasEntitlement(licenseId: "lic-1", code: "Pro plan") == false)
    }

    @Test("a second lookup inside the window makes no second request")
    func secondLookupInsideWindowMakesNoSecondRequest() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)
        let client = TamgaClient.mocked(performer)

        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")
        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "BETA")
        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "NOPE")

        #expect(await performer.requestCount == 1)
    }

    @Test("an entry goes stale once the window elapses")
    func entryGoesStaleOnceWindowElapses() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)
        let clock = MutableClock()
        let client = TamgaClient.mocked(performer, now: { clock.now })

        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")
        clock.advance(by: EntitlementCache.ttl - 1)
        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")
        #expect(await performer.requestCount == 1)

        clock.advance(by: 2)
        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")
        #expect(await performer.requestCount == 2)
    }

    @Test("invalidating forces a refetch")
    func invalidatingForcesRefetch() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)
        let client = TamgaClient.mocked(performer)

        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")
        await client.invalidateEntitlementCache(licenseId: "lic-1")
        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")

        #expect(await performer.requestCount == 2)
    }

    @Test("separate licenses are cached separately")
    func separateLicensesAreCachedSeparately() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)
        let client = TamgaClient.mocked(performer)

        _ = try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")
        _ = try await client.hasEntitlement(licenseId: "lic-2", code: "PRO")

        #expect(await performer.requestCount == 2)
    }

    @Test("the lookup requests the server maximum page size")
    func lookupRequestsServerMaximumPageSize() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)

        _ = try await TamgaClient.mocked(performer).hasEntitlement(licenseId: "lic-1", code: "PRO")

        #expect(await performer.request(at: 0)?.url?.query?
            .contains("limit=\(TamgaClient.entitlementLookupPageSize)") == true)
    }

    @Test("listEntitlements synthesizes a cursor only for a full page")
    func listEntitlementsSynthesizesCursorOnlyForFullPage() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)

        let page = try await TamgaClient.mocked(performer).listEntitlements(
            licenseId: "lic-1", options: ListOptions(limit: 2))

        #expect(page.items.count == 2)
        // A full page means there may be more, so the cursor is the last id.
        #expect(page.nextCursor == "ent-2")
    }

    @Test("a short page ends the pagination")
    func shortPageEndsPagination() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)

        let page = try await TamgaClient.mocked(performer).listEntitlements(
            licenseId: "lic-1", options: ListOptions(limit: 50))

        #expect(page.items.count == 2)
        #expect(page.nextCursor == nil)
    }

    @Test("a page cursor is sent as the keyset parameter")
    func pageCursorIsSentAsKeysetParameter() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: "{\"data\":[]}")

        _ = try await TamgaClient.mocked(performer).listComponents(
            machineId: "mach-1", options: ListOptions(after: "comp-9", limit: 10))

        let query = await performer.request(at: 0)?.url?.query ?? ""
        #expect(query.contains("page%5Bafter%5D=comp-9") || query.contains("page[after]=comp-9"))
    }

    @Test("getEntitlement fetches a single resource")
    func getEntitlementFetchesSingleResource() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"ent-1","type":"entitlements","attributes":{"code":"PRO","name":"Pro"}}}
        """)

        let entitlement = try await TamgaClient.mocked(performer).getEntitlement(
            licenseId: "lic-1", entitlementId: "ent-1")

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/entitlements/ent-1")
        #expect(entitlement.code == "PRO")
    }

    @Test("concurrent lookups are race free")
    func concurrentLookupsAreRaceFree() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.twoEntitlements)
        let client = TamgaClient.mocked(performer)

        // Actor isolation is what makes this safe; the point here is that a
        // burst of concurrent lookups neither deadlocks nor returns a wrong
        // answer, which it would if the cache were read while a fetch held it.
        try await withThrowingTaskGroup(of: Bool.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    try await client.hasEntitlement(licenseId: "lic-1", code: "PRO")
                }
            }
            for try await found in group {
                #expect(found)
            }
        }
    }
}

/// A clock a test can move forward, for exercising cache expiry without
/// sleeping.
final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current = Date(timeIntervalSince1970: 1_700_000_000)

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(by seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        current = current.addingTimeInterval(seconds)
    }
}
