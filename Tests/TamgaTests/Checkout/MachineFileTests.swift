import Crypto
import CryptoExtras
import Foundation
import Testing

@testable import Tamga

@Suite("MachineFile")
struct MachineFileTests {
    @Test("verify succeeds for a valid Ed25519-signed file")
    func verifySucceedsForEd25519() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation))
    }

    @Test("verify succeeds for a valid ECDSA-P256-signed file")
    func verifySucceedsForEcdsaP256() throws {
        let key = P256.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ecdsaSign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ecdsa-p256+v2")

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .ecdsaP256Sign, publicKey: key.publicKey.derRepresentation))
    }

    @Test("verify succeeds for a valid RSA-PKCS1-signed file")
    func verifySucceedsForRsaPkcs1() throws {
        let pair = RsaTestKey.generate()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let padding = _RSA.Signing.Padding.insecurePKCS1v1_5
        let sig = CheckoutFixture.rsaSign(enc: enc, privateKey: pair.privateKey, padding: padding)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+rsa-sha256+v2")

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .rsa2048Pkcs1Sign, publicKey: pair.publicKeySPKI))
    }

    @Test("verify succeeds for a valid RSA-PSS-signed file")
    func verifySucceedsForRsaPss() throws {
        let pair = RsaTestKey.generate()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let padding = _RSA.Signing.Padding.PSS
        let sig = CheckoutFixture.rsaSign(enc: enc, privateKey: pair.privateKey, padding: padding)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+rsa-pss-sha256+v2")

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .rsa2048Pkcs1PssSign, publicKey: pair.publicKeySPKI))
    }

    @Test("verify treats .none scheme the same as Ed25519 (server default)")
    func verifyNoneSchemeDefaultsToEd25519() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .none, publicKey: key.publicKey.rawRepresentation))
    }

    /// GOTCHA regression: RSA_2048_JWT_RS256 must be explicitly rejected,
    /// never silently routed to another RSA verifier -- the algorithm-
    /// confusion risk this SDK family's own docs call out repeatedly.
    @Test("verify throws schemeNotSupported for RSA_2048_JWT_RS256, never attempting verification")
    func verifyThrowsForJwtRs256Scheme() throws {
        let pair = RsaTestKey.generate()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        // Even a validly-signed PKCS1 signature must not slip through under
        // the JWT scheme -- the scheme itself is rejected before any
        // signature check runs.
        let padding = _RSA.Signing.Padding.insecurePKCS1v1_5
        let sig = CheckoutFixture.rsaSign(enc: enc, privateKey: pair.privateKey, padding: padding)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+rsa-sha256+v2")

        let file = try MachineFile.parse(pem)
        let expectedMessage =
            "RSA_2048_JWT_RS256 is rejected server-side for machine files (422 SCHEME_NOT_SUPPORTED) " +
            "and is not implemented client-side either -- this SDK never attempts JWT/RS256 verification."
        #expect(throws: TamgaCheckoutError.schemeNotSupported(expectedMessage)) {
            _ = try file.verify(scheme: .rsa2048JwtRs256, publicKey: pair.publicKeySPKI)
        }
    }

    @Test("verifyAndDecrypt returns the embedded Machine for a valid plain (unencrypted) file")
    func verifyAndDecryptReturnsMachineForPlainFile() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let fingerprint = "plain-fingerprint-xyz"
        let json = CheckoutFixture.machinePayloadJSON(fingerprint: fingerprint)
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try MachineFile.parse(pem)
        let machine = try file.verifyAndDecrypt(
            scheme: .ed25519Sign, publicKey: signingKey.publicKey.rawRepresentation,
            licenseKey: "unused-for-plain", fingerprint: fingerprint
        )

        #expect(machine.id == "mach_123")
        #expect(machine.fingerprint == fingerprint)
    }

    @Test("verifyAndDecrypt returns the embedded Machine for a valid encrypted file")
    func verifyAndDecryptReturnsMachineForEncryptedFile() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let licenseKey = "TAMGA-LICENSE-KEY"
        let fingerprint = "machine-fingerprint-xyz"
        let aesKey = Hkdf.deriveMachineFileKey(licenseKey: licenseKey, fingerprint: fingerprint)
        let json = CheckoutFixture.machinePayloadJSON(fingerprint: fingerprint)
        let enc = CheckoutFixture.machineEncryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519+v2")

        let file = try MachineFile.parse(pem)
        let machine = try file.verifyAndDecrypt(
            scheme: .ed25519Sign, publicKey: signingKey.publicKey.rawRepresentation,
            licenseKey: licenseKey, fingerprint: fingerprint
        )

        #expect(machine.id == "mach_123")
        #expect(machine.fingerprint == fingerprint)
    }

    @Test("verifyAndDecrypt throws decryptionFailed for the wrong fingerprint on an encrypted file")
    func verifyAndDecryptThrowsForWrongFingerprint() throws {
        // GOTCHA regression: machine-file decryption binds BOTH the license
        // key AND the fingerprint via HKDF's `info` parameter -- a correct
        // license key with the wrong fingerprint must still fail closed.
        let signingKey = Curve25519.Signing.PrivateKey()
        let licenseKey = "TAMGA-LICENSE-KEY"
        let realFingerprint = "real-fingerprint"
        let aesKey = Hkdf.deriveMachineFileKey(licenseKey: licenseKey, fingerprint: realFingerprint)
        let json = CheckoutFixture.machinePayloadJSON(fingerprint: realFingerprint)
        let enc = CheckoutFixture.machineEncryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519+v2")

        let file = try MachineFile.parse(pem)
        // Distinct from signatureVerificationFailed -- the Ed25519 signature
        // over `enc` is genuinely valid here; only the AES-GCM decrypt step
        // (HKDF derives a different key for the wrong fingerprint) fails.
        let expectedMessage =
            "Encrypted machine file failed to decrypt -- verify the license key (and fingerprint, for machine " +
            "files) are correct, or the file may be corrupted."
        #expect(throws: TamgaCheckoutError.decryptionFailed(expectedMessage)) {
            _ = try file.verifyAndDecrypt(
                scheme: .ed25519Sign, publicKey: signingKey.publicKey.rawRepresentation,
                licenseKey: licenseKey, fingerprint: "wrong-fingerprint"
            )
        }
    }

    @Test("parse throws offlineFileFormat for a missing BEGIN marker")
    func parseThrowsForMissingBeginMarker() {
        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineFile.parse("not a pem file\n-----END MACHINE FILE-----")
        }
    }

    @Test("parse throws offlineFileFormat for malformed base64 body")
    func parseThrowsForMalformedBase64() {
        let pem = "-----BEGIN MACHINE FILE-----\nnot valid base64!!!\n-----END MACHINE FILE-----"
        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineFile.parse(pem)
        }
    }

    @Test("parse throws offlineFileFormat for a body that's valid base64 but not valid certificate JSON")
    func parseThrowsForMalformedCertificateJSON() {
        let body = Data("not a certificate".utf8).base64EncodedString()
        let pem = "-----BEGIN MACHINE FILE-----\n\(body)\n-----END MACHINE FILE-----"
        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineFile.parse(pem)
        }
    }

    @Test("verify returns false for a malformed base64 signature")
    func verifyReturnsFalseForMalformedBase64Signature() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pem = CheckoutFixture.wrapMachinePEM(enc: "AA==", sig: "not valid base64!!!", alg: "base64+ed25519+v2")

        let file = try MachineFile.parse(pem)
        #expect(try !file.verify(scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation))
    }

    @Test("verifyAndDecrypt throws offlineFileFormat when enc is not valid base64")
    func verifyAndDecryptThrowsForMalformedEncBase64() throws {
        let key = Curve25519.Signing.PrivateKey()
        let enc = "not valid base64!!!"
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try MachineFile.parse(pem)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try file.verifyAndDecrypt(
                scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
                licenseKey: "unused", fingerprint: "unused"
            )
        }
    }

    @Test("verifyAndDecrypt throws offlineFileFormat for a decoded payload that's not valid resource JSON")
    func verifyAndDecryptThrowsForMalformedPayloadJSON() throws {
        let key = Curve25519.Signing.PrivateKey()
        let enc = Data("not resource json".utf8).base64EncodedString()
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "base64+ed25519+v2")

        let file = try MachineFile.parse(pem)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try file.verifyAndDecrypt(
                scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
                licenseKey: "unused", fingerprint: "unused"
            )
        }
    }

    /// Every one of these is a malformed encrypted `enc`, and none may reach
    /// AES-GCM. The single-blob shapes matter most: they are exactly what this
    /// SDK used to hand the decryptor, and what it must now refuse.
    @Test(
        "verifyAndDecrypt throws offlineFileFormat for malformed encrypted enc framings",
        arguments: [
            Data([0x01, 0x02, 0x03]).base64EncodedString(),          // one blob, far too short
            Data(repeating: 0x41, count: 64).base64EncodedString(),  // one blob, plausible length, no dot
            "AAAAAAAAAAAAAAAA",                                       // valid base64, still no dot
            "not-base64.also-not-base64",                             // dot pair, neither half decodes
            "QUFBQUFBQUFBQUFB.",                                      // 12-byte nonce, empty ciphertext half
            ".QUFBQUFBQUFBQUFB",                                      // empty nonce half
            "QQ==.QUFBQUFBQUFBQUFBQUFBQQ==",                          // 1-byte nonce, not 12
            "QUFBQUFBQUFBQUFB.QUFB",                                  // ciphertext shorter than the GCM tag
            "QUFBQUFBQUFBQUFB.QUFB.QUFB"                              // three parts, not two
        ]
    )
    func verifyAndDecryptThrowsForMalformedEncryptedFraming(enc: String) throws {
        let key = Curve25519.Signing.PrivateKey()
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapMachinePEM(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519+v2")

        let file = try MachineFile.parse(pem)
        #expect(throws: TamgaCheckoutError.self) {
            _ = try file.verifyAndDecrypt(
                scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation,
                licenseKey: "unused", fingerprint: "unused"
            )
        }
    }

    @Test("validateTtl accepts values within (0, 31536000]")
    func validateTtlAcceptsValidRange() throws {
        try MachineFile.validateTtl(1)
        try MachineFile.validateTtl(MachineFile.maxTtlSeconds)
    }

    @Test("validateTtl throws ttlInvalid for zero, negative, and over-max values")
    func validateTtlRejectsInvalidValues() {
        for invalid in [0, -1, MachineFile.maxTtlSeconds + 1] {
            #expect(throws: TamgaCheckoutError.self) {
                try MachineFile.validateTtl(invalid)
            }
        }
    }
}
