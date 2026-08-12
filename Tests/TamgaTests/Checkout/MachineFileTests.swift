import CryptoKit
import Foundation
import Testing

@testable import Tamga

@Suite("MachineFile")
struct MachineFileTests {
    private static let begin = "-----BEGIN MACHINE FILE-----"
    private static let end = "-----END MACHINE FILE-----"

    @Test("verify succeeds for a valid Ed25519-signed file")
    func verifySucceedsForEd25519() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "base64+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .ed25519Sign, publicKey: key.publicKey.rawRepresentation))
    }

    @Test("verify succeeds for a valid ECDSA-P256-signed file")
    func verifySucceedsForEcdsaP256() throws {
        let key = P256.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ecdsaSign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "ecdsa-sha256"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .ecdsaP256Sign, publicKey: key.publicKey.derRepresentation))
    }

    @Test("verify succeeds for a valid RSA-PKCS1-signed file")
    func verifySucceedsForRsaPkcs1() throws {
        let pair = RsaTestKey.generate()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.rsaSign(enc: enc, privateKey: pair.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "rsa-sha256"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .rsa2048Pkcs1Sign, publicKey: pair.publicKeySPKI))
    }

    @Test("verify succeeds for a valid RSA-PSS-signed file")
    func verifySucceedsForRsaPss() throws {
        let pair = RsaTestKey.generate()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.rsaSign(enc: enc, privateKey: pair.privateKey, algorithm: .rsaSignatureMessagePSSSHA256)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "rsa-pss-sha256"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try MachineFile.parse(pem)
        #expect(try file.verify(scheme: .rsa2048Pkcs1PssSign, publicKey: pair.publicKeySPKI))
    }

    @Test("verify treats .none scheme the same as Ed25519 (server default)")
    func verifyNoneSchemeDefaultsToEd25519() throws {
        let key = Curve25519.Signing.PrivateKey()
        let json = CheckoutFixture.machinePayloadJSON()
        let enc = CheckoutFixture.plainEnc(json: json)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: key)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "base64+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

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
        let sig = CheckoutFixture.rsaSign(enc: enc, privateKey: pair.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "rsa-sha256"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try MachineFile.parse(pem)
        #expect(throws: TamgaCheckoutError.schemeNotSupported("RSA_2048_JWT_RS256 is rejected server-side for machine files (422 SCHEME_NOT_SUPPORTED) and is not implemented client-side either -- this SDK never attempts JWT/RS256 verification.")) {
            _ = try file.verify(scheme: .rsa2048JwtRs256, publicKey: pair.publicKeySPKI)
        }
    }

    @Test("verifyAndDecrypt returns the embedded Machine for a valid encrypted file")
    func verifyAndDecryptReturnsMachineForEncryptedFile() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let licenseKey = "TAMGA-LICENSE-KEY"
        let fingerprint = "machine-fingerprint-xyz"
        let aesKey = Hkdf.deriveMachineFileKey(licenseKey: licenseKey, fingerprint: fingerprint)
        let json = CheckoutFixture.machinePayloadJSON(fingerprint: fingerprint)
        let enc = CheckoutFixture.encryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try MachineFile.parse(pem)
        let machine = try file.verifyAndDecrypt(scheme: .ed25519Sign, publicKey: signingKey.publicKey.rawRepresentation, licenseKey: licenseKey, fingerprint: fingerprint)

        #expect(machine.id == "mach_123")
        #expect(machine.fingerprint == fingerprint)
    }

    @Test("verifyAndDecrypt throws signatureVerificationFailed for the wrong fingerprint on an encrypted file")
    func verifyAndDecryptThrowsForWrongFingerprint() throws {
        // GOTCHA regression: machine-file decryption binds BOTH the license
        // key AND the fingerprint via HKDF's `info` parameter -- a correct
        // license key with the wrong fingerprint must still fail closed.
        let signingKey = Curve25519.Signing.PrivateKey()
        let licenseKey = "TAMGA-LICENSE-KEY"
        let realFingerprint = "real-fingerprint"
        let aesKey = Hkdf.deriveMachineFileKey(licenseKey: licenseKey, fingerprint: realFingerprint)
        let json = CheckoutFixture.machinePayloadJSON(fingerprint: realFingerprint)
        let enc = CheckoutFixture.encryptedEnc(json: json, key: aesKey)
        let sig = CheckoutFixture.ed25519Sign(enc: enc, privateKey: signingKey)
        let pem = CheckoutFixture.wrapInPEM(certificate: .init(enc: enc, sig: sig, alg: "aes-256-gcm+ed25519"), beginMarker: Self.begin, endMarker: Self.end)

        let file = try MachineFile.parse(pem)
        #expect(throws: TamgaCheckoutError.signatureVerificationFailed) {
            _ = try file.verifyAndDecrypt(scheme: .ed25519Sign, publicKey: signingKey.publicKey.rawRepresentation, licenseKey: licenseKey, fingerprint: "wrong-fingerprint")
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
