import CryptoKit
import Foundation
import Testing

@testable import Tamga

@Suite("LicenseFile")
struct LicenseFileTests {
    private static let begin = "-----BEGIN LICENSE FILE-----"
    private static let end = "-----END LICENSE FILE-----"

    @Test("parse + verify succeeds for a valid plain (unencrypted) file")
    func verifySucceedsForValidPlainFile() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "base64+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        #expect(try file.verify(publicKey: key.publicKey.rawRepresentation))
    }

    @Test("verifyAndDecrypt decodes every License field -- timestamps and metadata included")
    func verifyAndDecryptDecodesFullLicenseFieldSet() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.fullLicensePayloadJSON(key: "TAMGA-FULL-FIELDS")
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "base64+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        let license = try file.verifyAndDecrypt(publicKey: key.publicKey.rawRepresentation, licenseKey: "unused-for-plain")

        #expect(license.uses == 3)
        #expect(license.expiry != nil)
        #expect(license.lastValidatedAt != nil)
        #expect(license.lastCheckInAt != nil)
        #expect(license.metadata?["seats"] == .int(5))
        #expect(license.metadata?["tier"] == .string("pro"))
        #expect(license.metadata?["trial"] == .bool(false))
        #expect(license.metadata?["note"] == .null)
    }

    @Test("verifyAndDecrypt returns the embedded License for a valid plain file")
    func verifyAndDecryptReturnsLicenseForPlainFile() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON(key: "TAMGA-ABC-123")
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "base64+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        let license = try file.verifyAndDecrypt(publicKey: key.publicKey.rawRepresentation, licenseKey: "unused-for-plain")

        #expect(license.id == "lic_123")
        #expect(license.key == "TAMGA-ABC-123")
        #expect(license.suspended == false)
    }

    @Test("verifyAndDecrypt returns the embedded License for a valid encrypted file")
    func verifyAndDecryptReturnsLicenseForEncryptedFile() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let licenseKey = "TAMGA-ENCRYPTED-KEY"
        let aesKey = NaiveKey.derive(licenseKey: licenseKey)
        let json = CheckoutFixture.licensePayloadJSON(key: licenseKey)
        let enc = CheckoutFixture.encryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        let license = try file.verifyAndDecrypt(publicKey: signingKey.publicKey.rawRepresentation, licenseKey: licenseKey)

        #expect(license.key == licenseKey)
    }

    @Test("verifyAndDecrypt throws signatureVerificationFailed for the wrong license key on an encrypted file")
    func verifyAndDecryptThrowsForWrongLicenseKey() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let aesKey = NaiveKey.derive(licenseKey: "REAL-KEY")
        let json = CheckoutFixture.licensePayloadJSON(key: "REAL-KEY")
        let enc = CheckoutFixture.encryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        #expect(throws: TamgaCheckoutError.signatureVerificationFailed) {
            _ = try file.verifyAndDecrypt(publicKey: signingKey.publicKey.rawRepresentation, licenseKey: "WRONG-KEY")
        }
    }

    /// CRITICAL regression: the Ed25519 signature must cover `enc`'s base64
    /// STRING bytes, not the decoded payload bytes. Confirm a signature
    /// computed over the DECODED bytes (the common implementation mistake)
    /// does NOT verify against this SDK's `verify`, which signs/verifies
    /// over the string form.
    @Test("verify fails when the signature was computed over enc's decoded bytes instead of its base64 string bytes")
    func verifyFailsForSignatureOverDecodedBytes() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)

        // Deliberately sign the DECODED bytes (json) instead of enc's string bytes.
        let wrongSignature = try key.signature(for: json)
        let pem = CheckoutFixture.wrapInPEM(
            certificate: .init(enc: enc, sig: wrongSignature.base64EncodedString(), alg: "base64+ed25519"),
            beginMarker: Self.begin, endMarker: Self.end
        )

        let file = try LicenseFile.parse(pem)
        #expect(!(try file.verify(publicKey: key.publicKey.rawRepresentation)))
    }

    @Test("verify returns false for a tampered enc payload")
    func verifyReturnsFalseForTamperedPayload() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc + "tampered", sig: sig, alg: "base64+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        #expect(!(try file.verify(publicKey: key.publicKey.rawRepresentation)))
    }

    @Test("verify returns false for the wrong public key")
    func verifyReturnsFalseForWrongKey() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "base64+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        #expect(!(try file.verify(publicKey: otherKey.publicKey.rawRepresentation)))
    }

    @Test("verify throws unsupportedAlgorithm for a non-ed25519 alg")
    func verifyThrowsForNonEd25519Alg() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: "AA==", sig: "AA==", alg: "base64+rsa"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try LicenseFile.parse(pem)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try file.verify(publicKey: key.publicKey.rawRepresentation)
        }
    }

    @Test("parse throws offlineFileFormat for a missing BEGIN marker")
    func parseThrowsForMissingBeginMarker() {
        #expect(throws: TamgaCheckoutError.self) {
            _ = try LicenseFile.parse("not a pem file\n-----END LICENSE FILE-----")
        }
    }

    @Test("parse throws offlineFileFormat, not a crash, for a short overlapping-marker string")
    func parseThrowsForShortOverlappingMarkers() {
        // SECURITY regression: a crafted string shorter than
        // beginMarker.count + endMarker.count that still independently
        // satisfies hasPrefix/hasSuffix must not crash the length
        // computation -- see PemEnvelope.swift's guard.
        #expect(throws: TamgaCheckoutError.self) {
            _ = try LicenseFile.parse(String(Self.begin.prefix(10)) + String(Self.end.suffix(10)))
        }
    }

    @Test("parse throws offlineFileFormat for malformed base64 body")
    func parseThrowsForMalformedBase64() {
        #expect(throws: TamgaCheckoutError.self) {
            _ = try LicenseFile.parse("\(Self.begin)\nnot valid base64!!!\n\(Self.end)")
        }
    }
}
