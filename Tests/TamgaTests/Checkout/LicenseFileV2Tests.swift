import Crypto
import Foundation
import Testing

@testable import Tamga

/// Format v2: the expiry lives inside the signature.
///
/// In v1 the `ttl` a caller asked for lived only in the JSON:API envelope
/// around the certificate, never inside the signed bytes. A 24-hour trial file
/// was therefore cryptographically valid forever: the client is the attacker,
/// so any check built on the envelope is bypassed by keeping -- or
/// redistributing -- the raw certificate string.
@Suite("LicenseFile format v2")
struct LicenseFileV2Tests {
    private static let exp: Int64 = 1_767_229_200

    private func pem(exp: Int64?, key: Curve25519.Signing.PrivateKey) -> String {
        let json = CheckoutFixture.licensePayloadJSON(exp: exp)
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        return CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")
    }

    @Test("an expired file is refused even though its signature is valid")
    func expiredFileIsRefused() throws {
        let key = Curve25519.Signing.PrivateKey()
        let file = try LicenseFile.parse(pem(exp: Self.exp, key: key))

        #expect(throws: TamgaCheckoutError.expired(Self.exp)) {
            _ = try file.verifyWithClaims(
                publicKey: key.publicKey.rawRepresentation,
                licenseKey: "TEST-LICENSE-KEY",
                now: Self.exp + 3600
            )
        }
    }

    @Test("a file within its ttl verifies and exposes its claims")
    func fileWithinTtlVerifies() throws {
        let key = Curve25519.Signing.PrivateKey()
        let file = try LicenseFile.parse(pem(exp: Self.exp, key: key))

        let (_, claims) = try file.verifyWithClaims(
            publicKey: key.publicKey.rawRepresentation,
            licenseKey: "TEST-LICENSE-KEY",
            now: Self.exp - 3600
        )
        #expect(claims.exp == Self.exp)
        #expect(claims.jti == "test-jti")
        #expect(claims.kid == "test-kid")
    }

    @Test("a file without an exp claim never expires")
    func fileWithoutExpNeverExpires() throws {
        // Checkout without a `ttl` produces no `exp`. That must read as
        // perpetual, not as "expired at the epoch".
        let key = Curve25519.Signing.PrivateKey()
        let file = try LicenseFile.parse(pem(exp: nil, key: key))

        let (_, claims) = try file.verifyWithClaims(
            publicKey: key.publicKey.rawRepresentation,
            licenseKey: "TEST-LICENSE-KEY",
            now: Int64.max / 2
        )
        #expect(claims.exp == nil)
    }

    @Test("clock skew tolerance is seconds, not hours")
    func clockSkewToleranceIsSmall() throws {
        // A generous allowance would just be a free extension on every expired
        // file, since the clock belongs to the attacker.
        let key = Curve25519.Signing.PrivateKey()
        let file = try LicenseFile.parse(pem(exp: Self.exp, key: key))
        let publicKey = key.publicKey.rawRepresentation

        _ = try file.verifyWithClaims(
            publicKey: publicKey, licenseKey: "TEST-LICENSE-KEY", now: Self.exp + 30
        )

        #expect(throws: TamgaCheckoutError.expired(Self.exp)) {
            _ = try file.verifyWithClaims(
                publicKey: publicKey, licenseKey: "TEST-LICENSE-KEY", now: Self.exp + 600
            )
        }
    }

    @Test("a v1 alg string is refused outright")
    func v1AlgIsRefused() throws {
        // Accepting both formats would hand back the permanent-file problem:
        // any certificate issued before v2 could be kept and reused forever.
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let v1 = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519")

        let file = try LicenseFile.parse(v1)
        #expect(throws: (any Error).self) {
            _ = try file.verify(publicKey: key.publicKey.rawRepresentation)
        }
    }
}
