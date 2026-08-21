import Foundation
import Testing

@testable import Tamga

@Suite("Auto-update check")
struct UpgradeCheckTests {
    private static let options = UpgradeCheckOptions(
        productId: "prod-9", platform: "darwin", filetype: "dmg", version: "1.0.0")

    @Test("the four required parameters are sent flat, not bracketed")
    func requiredParametersAreSentFlat() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.release)

        _ = try await TamgaClient.mocked(performer).checkForUpgrade(Self.options)

        let url = await performer.request(at: 0)?.url
        #expect(url?.path == "/v1/accounts/acct-123/releases/actions/upgrade")
        let query = url?.query ?? ""
        #expect(query.contains("product=prod-9"))
        #expect(query.contains("platform=darwin"))
        #expect(query.contains("filetype=dmg"))
        #expect(query.contains("version=1.0.0"))
        // Unset optionals are omitted, not sent empty: an empty `channel` is a
        // different request from an absent one.
        #expect(!query.contains("channel"))
        #expect(!query.contains("constraint"))
    }

    @Test("channel and constraint are sent when set")
    func optionalParametersAreSentWhenSet() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.release)

        _ = try await TamgaClient.mocked(performer).checkForUpgrade(
            UpgradeCheckOptions(productId: "prod-9", platform: "darwin", filetype: "dmg",
                                version: "1.0.0", channel: "stable", constraint: "^1"))

        let query = await performer.request(at: 0)?.url?.query ?? ""
        #expect(query.contains("channel=stable"))
        #expect(query.contains("constraint=%5E1"))
    }

    @Test("a 204 is nil rather than a decode failure")
    func noContentIsNil() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 204, body: "")

        let result = try await TamgaClient.mocked(performer).checkForUpgrade(Self.options)

        // Two server-side situations collapse into this one answer, deliberately:
        // no newer release, and a newer release this licence may not have. The
        // case is named for the second so nobody renders it as "up to date".
        #expect(result == .noneAvailable)
        #expect(result.release == nil)
    }

    @Test("a release decodes despite its camelCase attribute names")
    func releaseDecodesCamelCaseAttributes() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.release)

        let result = try await TamgaClient.mocked(performer).checkForUpgrade(Self.options)

        guard case .upgrade(let release) = result else {
            Issue.record("expected an upgrade, got \(result)")
            return
        }
        // `productId`, not `product_id` -- the one resource with a camelCase bag.
        #expect(release.productId == "prod-9")
        #expect(release.version == "2.0.0")
        #expect(release.channel == "stable")
        #expect(release.tag == "ga")
        #expect(release.created != nil)
        #expect(result.release == release)
    }

    @Test("an absent tag decodes rather than failing")
    func absentTagDecodes() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"rel-2","type":"releases","attributes":{"version":"3.0.0"}}}
        """)

        let result = try await TamgaClient.mocked(performer).checkForUpgrade(Self.options)

        #expect(result.release?.tag == nil)
        #expect(result.release?.id == "rel-2")
    }

    @Test("a suspended licence gets a 403, not a nil")
    func suspendedLicenceIsAnError() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 403, body: """
        {"errors":[{"code":"FORBIDDEN","detail":"The license is suspended"}]}
        """)

        await #expect(throws: TamgaError.self) {
            _ = try await TamgaClient.mocked(performer).checkForUpgrade(Self.options)
        }
    }
}
