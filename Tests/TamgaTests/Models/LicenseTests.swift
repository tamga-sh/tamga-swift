import Foundation
import Testing

@testable import Tamga

@Suite("License")
struct LicenseTests {
    private static func makeLicense(key: String = "KEY-1") -> License {
        License(
            id: "lic_1", key: key, suspended: false, expiry: nil,
            uses: 0, lastValidatedAt: nil, lastCheckInAt: nil, metadata: nil
        )
    }

    @Test("Equatable: two Licenses with identical fields compare equal")
    func equalLicensesCompareEqual() {
        #expect(Self.makeLicense() == Self.makeLicense())
    }

    @Test("Equatable: Licenses differing in a single field compare unequal")
    func differingLicensesCompareUnequal() {
        #expect(Self.makeLicense(key: "KEY-1") != Self.makeLicense(key: "KEY-2"))
    }

    @Test("fromResource flattens a JSON:API license resource into a License")
    func fromResourceFlattensCorrectly() throws {
        let json = CheckoutFixture.fullLicensePayloadJSON(key: "TAMGA-FULL-FIELDS")
        let payload = try TamgaJSONCoding.decoder.decode(JSONAPIPayload<LicenseAttributes>.self, from: json)

        let license = License.fromResource(payload.data)

        #expect(license.id == "lic_123")
        #expect(license.key == "TAMGA-FULL-FIELDS")
        #expect(license.uses == 3)
    }
}
