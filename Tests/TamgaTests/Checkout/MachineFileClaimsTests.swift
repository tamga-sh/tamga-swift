import Crypto
import Foundation
import Testing

@testable import Tamga

/// The signed `meta` claims a format-v2 machine file carries, and the expiry
/// they make enforceable.
///
/// These used not to exist for machine files: the type's own doc comment
/// asserted that a machine file "carries no signed `meta` claims" and that its
/// expiry "is not enforced client-side here". Both statements were false by the
/// time they were read -- `check_out_machine.rs` signs the same
/// `LicenseFileClaims` struct the license path does -- so a machine file with a
/// one-hour TTL verified forever.
///
/// Split from `MachineFileTests` to keep both under the 300-line type-body lint
/// ceiling.
@Suite("MachineFile — signed claims")
struct MachineFileClaimsTests {
    @Test("verifyWithClaims returns the signed iat/jti/kid alongside the machine")
    func verifyWithClaimsReturnsTheSignedClaims() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let result = try MachineFile.parse(pem).verifyWithClaims(
            scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
            licenseKey: "unused", fingerprint: "unused",
            now: CheckoutFixture.machineFixtureIat
        )

        #expect(result.machine.id == "mach_123")
        #expect(result.claims.iat == CheckoutFixture.machineFixtureIat)
        #expect(result.claims.jti == "test-machine-jti")
        #expect(result.claims.kid == "test-machine-kid")
        // Checked out with no ttl: no exp, and legitimately so.
        #expect(result.claims.exp == nil)
    }

    /// A checkout made without a `ttl` genuinely never expires --
    /// `check_out_machine.rs` sets `exp` from an `Option`. Absence must not be
    /// mistaken for a malformed file.
    @Test("a file with no exp claim verifies at any clock")
    func fileWithoutExpNeverExpires() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")
        let file = try MachineFile.parse(pem)

        for now in [CheckoutFixture.machineFixtureIat, CheckoutFixture.machineFixtureIat + 10_000_000_000] {
            let result = try file.verifyWithClaims(
                scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
                licenseKey: "unused", fingerprint: "unused", now: now
            )
            #expect(result.claims.exp == nil)
        }
    }

    @Test("a past exp is enforced, with the same 60s tolerance the license-file path uses")
    func expiryIsEnforcedWithTheSharedTolerance() throws {
        let key = Curve25519.Signing.PrivateKey()
        let exp = CheckoutFixture.machineFixtureIat + 3600
        let json = CheckoutFixture.machinePayloadJSON(exp: exp)
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")
        let file = try MachineFile.parse(pem)

        func verify(at now: Int64) throws -> Machine {
            try file.verifyWithClaims(
                scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
                licenseKey: "unused", fingerprint: "unused", now: now
            ).machine
        }

        // Exactly on the tolerance boundary: still valid. The tolerance is
        // `LicenseFile`'s, deliberately -- one constant for both file types, so
        // they cannot drift into different grace periods.
        #expect(try verify(at: exp + LicenseFile.clockSkewToleranceSeconds).id == "mach_123")

        #expect(throws: TamgaCheckoutError.expired(exp)) {
            _ = try verify(at: exp + LicenseFile.clockSkewToleranceSeconds + 1)
        }
    }

    /// `alg` is outside the signature, so a v1 payload can be re-labelled `+v2`
    /// without breaking it. The claims check is the second gate that catches
    /// that.
    @Test("a payload with no signed meta claims is rejected as a pre-v2 file")
    func payloadWithoutClaimsIsRejected() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSONWithoutClaims()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineFile.parse(pem).verifyAndDecrypt(
                scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
                licenseKey: "unused", fingerprint: "unused"
            )
        }
    }

    @Test("verifyAndDecrypt reads the system clock, so an already-expired file is rejected")
    func verifyAndDecryptEnforcesExpiryAgainstTheSystemClock() throws {
        let key = Curve25519.Signing.PrivateKey()
        // Well in the past, so the assertion cannot depend on when it runs.
        let exp: Int64 = 1_000_000_000
        let json = CheckoutFixture.machinePayloadJSON(exp: exp)
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        #expect(throws: TamgaCheckoutError.expired(exp)) {
            _ = try MachineFile.parse(pem).verifyAndDecrypt(
                scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
                licenseKey: "unused", fingerprint: "unused"
            )
        }
    }
}
