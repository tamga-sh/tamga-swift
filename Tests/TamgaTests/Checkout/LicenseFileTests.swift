import Crypto
import Foundation
import Testing

@testable import Tamga

@Suite("LicenseFile")
struct LicenseFileTests {
    @Test("parse + verify succeeds for a valid plain (unencrypted) file")
    func verifySucceedsForValidPlainFile() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        #expect(try file.verify(publicKey: key.publicKey.rawRepresentation))
    }

    @Test("verifyAndDecrypt decodes every License field -- timestamps and metadata included")
    func verifyAndDecryptDecodesFullLicenseFieldSet() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.fullLicensePayloadJSON(key: "TAMGA-FULL-FIELDS")
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        let license = try file.verifyAndDecrypt(
            publicKey: key.publicKey.rawRepresentation, licenseKey: "unused-for-plain"
        )

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
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        let license = try file.verifyAndDecrypt(
            publicKey: key.publicKey.rawRepresentation, licenseKey: "unused-for-plain"
        )

        #expect(license.id == "lic_123")
        #expect(license.key == "TAMGA-ABC-123")
        #expect(license.suspended == false)
    }

    @Test("verifyAndDecrypt returns the embedded License for a valid encrypted file")
    func verifyAndDecryptReturnsLicenseForEncryptedFile() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let licenseKey = "TAMGA-ENCRYPTED-KEY"
        let aesKey = Hkdf.deriveLicenseFileKey(licenseKey: licenseKey)
        let json = CheckoutFixture.licensePayloadJSON(key: licenseKey)
        let enc = CheckoutFixture.encryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        let license = try file.verifyAndDecrypt(
            publicKey: signingKey.publicKey.rawRepresentation, licenseKey: licenseKey
        )

        #expect(license.key == licenseKey)
    }

    @Test("verifyAndDecrypt throws decryptionFailed for the wrong license key on an encrypted file")
    func verifyAndDecryptThrowsForWrongLicenseKey() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let aesKey = Hkdf.deriveLicenseFileKey(licenseKey: "REAL-KEY")
        let json = CheckoutFixture.licensePayloadJSON(key: "REAL-KEY")
        let enc = CheckoutFixture.encryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        // Distinct from signatureVerificationFailed -- the Ed25519 signature
        // over `enc` is genuinely valid here; only the AES-GCM decrypt step
        // (wrong key) fails. See TamgaCheckoutError.decryptionFailed's docs.
        let expectedMessage =
            "Encrypted license file failed to decrypt -- verify the license key (and fingerprint, for machine " +
            "files) are correct, or the file may be corrupted."
        #expect(throws: TamgaCheckoutError.decryptionFailed(expectedMessage)) {
            _ = try file.verifyAndDecrypt(publicKey: signingKey.publicKey.rawRepresentation, licenseKey: "WRONG-KEY")
        }
    }

    /// CRITICAL regression: the Ed25519 signature must cover `enc`'s base64
    /// STRING bytes, not the decoded payload bytes. Confirm a signature
    /// computed over the DECODED bytes (the common implementation mistake)
    /// does NOT verify against this SDK's `verify`, which signs/verifies
    /// over the string form.
    @Test("verify fails when the signature was computed over enc's decoded bytes, not its base64 string bytes")
    func verifyFailsForSignatureOverDecodedBytes() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)

        // Deliberately sign the DECODED bytes (json) instead of enc's string bytes.
        let wrongSignature = try key.signature(for: json)
        let sig = wrongSignature.base64EncodedString()
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        let verified = try file.verify(publicKey: key.publicKey.rawRepresentation)
        #expect(!verified)
    }

    @Test("verify returns false for a tampered enc payload")
    func verifyReturnsFalseForTamperedPayload() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc + "tampered", sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        let verified = try file.verify(publicKey: key.publicKey.rawRepresentation)
        #expect(!verified)
    }

    @Test("verify returns false for the wrong public key")
    func verifyReturnsFalseForWrongKey() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.licensePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        let verified = try file.verify(publicKey: otherKey.publicKey.rawRepresentation)
        #expect(!verified)
    }

    @Test("verify throws unsupportedAlgorithm for a non-ed25519 alg")
    func verifyThrowsForNonEd25519Alg() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pem = CheckoutFixture.wrapLicensePEM(enc: "AA==", sig: "AA==", alg: "base64+rsa")

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
        //
        // Construction: beginMarker + endMarker.dropFirst(5). beginMarker's
        // own trailing 5 dashes double as endMarker's leading 5 dashes, so
        // the 49-char result independently satisfies hasPrefix(beginMarker)
        // (true by construction) AND hasSuffix(endMarker) (its last 26
        // characters reassemble endMarker byte-for-byte: beginMarker's
        // trailing "-----" + endMarker.dropFirst(5)'s "END LICENSE
        // FILE-----" == endMarker) -- while being 5 bytes shorter than
        // beginMarker.count + endMarker.count (28 + 26 = 54), which is
        // exactly the condition the length guard exists to catch.
        //
        // CORRECTNESS regression (on the test itself, not the guard): a
        // prior version of this test used `begin.prefix(10) +
        // end.suffix(10)`, which -- confirmed by direct inspection --
        // doesn't even satisfy hasPrefix(beginMarker), so it fails at the
        // guard on line 7 of PemEnvelope.swift ("missing begin marker")
        // and never reaches the length guard at all. It passed, but for the
        // wrong reason: coverage showed the length-guard lines as never hit.
        let begin = "-----BEGIN LICENSE FILE-----"
        let end = "-----END LICENSE FILE-----"
        let overlapping = begin + end.dropFirst(5)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try LicenseFile.parse(overlapping)
        }
    }

    @Test("parse throws offlineFileFormat for malformed base64 body")
    func parseThrowsForMalformedBase64() {
        let pem = "-----BEGIN LICENSE FILE-----\nnot valid base64!!!\n-----END LICENSE FILE-----"
        #expect(throws: TamgaCheckoutError.self) {
            _ = try LicenseFile.parse(pem)
        }
    }

    @Test("parse throws offlineFileFormat for a body that's valid base64 but not valid certificate JSON")
    func parseThrowsForMalformedCertificateJSON() {
        let body = Data("not a certificate".utf8).base64EncodedString()
        let pem = "-----BEGIN LICENSE FILE-----\n\(body)\n-----END LICENSE FILE-----"
        #expect(throws: TamgaCheckoutError.self) {
            _ = try LicenseFile.parse(pem)
        }
    }

    @Test("verify returns false for a malformed base64 signature")
    func verifyReturnsFalseForMalformedBase64Signature() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pem = CheckoutFixture.wrapLicensePEM(enc: "AA==", sig: "not valid base64!!!", alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        #expect(try !file.verify(publicKey: key.publicKey.rawRepresentation))
    }

    @Test("verifyAndDecrypt throws offlineFileFormat when enc is not valid base64")
    func verifyAndDecryptThrowsForMalformedEncBase64() throws {
        // Ed25519 signs arbitrary bytes regardless of whether they happen to
        // be valid base64, so `verify()` succeeds here -- the malformed-base64
        // failure is specific to verifyAndDecrypt's own decode step.
        let key = Curve25519.Signing.PrivateKey()
        let enc = "not valid base64!!!"
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try file.verifyAndDecrypt(publicKey: key.publicKey.rawRepresentation, licenseKey: "unused")
        }
    }

    @Test("verifyAndDecrypt throws offlineFileFormat for a decoded payload that's not valid resource JSON")
    func verifyAndDecryptThrowsForMalformedPayloadJSON() throws {
        let key = Curve25519.Signing.PrivateKey()
        let enc = Data("not resource json".utf8).base64EncodedString()
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try file.verifyAndDecrypt(publicKey: key.publicKey.rawRepresentation, licenseKey: "unused")
        }
    }

    @Test("verifyAndDecrypt throws offlineFileFormat for an encrypted payload shorter than nonce+tag")
    func verifyAndDecryptThrowsForShortEncryptedPayload() throws {
        let key = Curve25519.Signing.PrivateKey()
        let enc = Data([0x01, 0x02, 0x03]).base64EncodedString() // far shorter than 12+16 bytes
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapLicensePEM(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519+v2")

        let file = try LicenseFile.parse(pem)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try file.verifyAndDecrypt(publicKey: key.publicKey.rawRepresentation, licenseKey: "unused")
        }
    }
}
