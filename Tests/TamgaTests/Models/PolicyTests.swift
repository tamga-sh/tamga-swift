import Testing

@testable import Tamga

@Suite("LicenseScheme")
struct LicenseSchemeTests {
    @Test("wireValue maps every known wire string to its case")
    func mapsKnownWireValues() {
        #expect(LicenseScheme(wireValue: "ED25519_SIGN") == .ed25519Sign)
        #expect(LicenseScheme(wireValue: "RSA_2048_PKCS1_SIGN") == .rsa2048Pkcs1Sign)
        #expect(LicenseScheme(wireValue: "RSA_2048_PKCS1_PSS_SIGN") == .rsa2048Pkcs1PssSign)
        #expect(LicenseScheme(wireValue: "ECDSA_P256_SIGN") == .ecdsaP256Sign)
        #expect(LicenseScheme(wireValue: "RSA_2048_JWT_RS256") == .rsa2048JwtRs256)
    }

    @Test("wireValue maps nil and empty string to .none")
    func mapsMissingValueToNone() {
        #expect(LicenseScheme(wireValue: nil) == .none)
        #expect(LicenseScheme(wireValue: "") == .none)
    }

    @Test("wireValue falls back to .none for an unrecognized string, without throwing")
    func mapsUnrecognizedValueToNone() {
        #expect(LicenseScheme(wireValue: "SOME_FUTURE_SCHEME") == .none)
    }
}
