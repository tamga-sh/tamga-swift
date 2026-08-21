import Crypto
import CryptoExtras
import Foundation

@testable import Tamga

/// Test-only helpers for building real, correctly-shaped PEM-wrapped
/// checkout certificates (`.lic`/`.machine` file bodies) -- signs with this
/// SDK's own crypto primitives (Ed25519/RSA/ECDSA + AES-GCM), since there's
/// no independent reference-implementation fixture available in this repo.
/// The crypto primitives themselves are already tested against CryptoKit's
/// own sign/verify pair (including adversarial mismatched-curve cases, see
/// `EcdsaTests.swift`) -- these fixtures exist to exercise the
/// parsing/dispatch/decrypt WIRING in `LicenseFile`/`MachineFile`, not to
/// re-prove the primitives are individually correct.
enum CheckoutFixture {
    struct Certificate: Encodable {
        let enc: String
        let sig: String
        let alg: String
    }

    /// Builds a base64 `enc` payload for a plain (unencrypted) file: base64
    /// of the raw JSON bytes.
    static func plainEnc(json: Data) -> String {
        json.base64EncodedString()
    }

    /// Builds a base64 `enc` payload for an AES-256-GCM-encrypted LICENSE
    /// file: base64 of `nonce || ciphertext || tag`, matching
    /// `encode_license_file`'s single-buffer framing.
    ///
    /// Not interchangeable with `machineEncryptedEnc` below -- see that
    /// function, and `EncryptedPayloadDecryptor`, for why the two file types
    /// genuinely differ.
    static func encryptedEnc(json: Data, key: Data) -> String {
        let sealed = seal(json: json, key: key)
        var combined = sealed.nonce
        combined.append(sealed.ciphertext)
        combined.append(sealed.tag)
        return combined.base64EncodedString()
    }

    /// Builds an `enc` payload for an AES-256-GCM-encrypted MACHINE file:
    /// `"<nonce_b64>.<cipher_b64>"`, with the tag appended to the ciphertext
    /// half, matching `FieldEncryption::encrypt`.
    ///
    /// The halves are base64-encoded separately, so the result is not itself
    /// valid base64. Cross-checked against the server-issued fixtures in
    /// `Tests/TamgaTests/Fixtures/MachineFiles/` rather than trusted on its
    /// own -- a self-generated fixture that reproduces the SDK's own misreading
    /// of the format is exactly how the bug this replaces survived.
    static func machineEncryptedEnc(json: Data, key: Data) -> String {
        let sealed = seal(json: json, key: key)
        var ciphertextAndTag = sealed.ciphertext
        ciphertextAndTag.append(sealed.tag)
        return "\(sealed.nonce.base64EncodedString()).\(ciphertextAndTag.base64EncodedString())"
    }

    /// The three parts an AES-GCM seal produces, which the two `enc` framings
    /// then assemble differently.
    struct SealedParts {
        let nonce: Data
        let ciphertext: Data
        let tag: Data
    }

    private static func seal(json: Data, key: Data) -> SealedParts {
        let nonce = Data((0..<AesGcmCipher.nonceLength).map { _ in UInt8.random(in: .min ... .max) })
        guard let (ciphertext, tag) = try? AesGcmCipher.seal(key: key, nonce: nonce, plaintext: json) else {
            fatalError("CheckoutFixture.seal: AES-GCM seal unexpectedly failed")
        }
        return SealedParts(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }

    /// Signs `enc`'s base64 STRING bytes (not decoded bytes) with an Ed25519
    /// key, matching the real wire contract.
    static func ed25519Sign(enc: String, privateKey: Curve25519.Signing.PrivateKey) -> String {
        let message = Data(enc.utf8)
        guard let signature = try? privateKey.signature(for: message) else {
            fatalError("CheckoutFixture.ed25519Sign: signing unexpectedly failed")
        }
        return signature.base64EncodedString()
    }

    static func ecdsaSign(enc: String, privateKey: P256.Signing.PrivateKey) -> String {
        let message = Data(enc.utf8)
        guard let signature = try? privateKey.signature(for: message) else {
            fatalError("CheckoutFixture.ecdsaSign: signing unexpectedly failed")
        }
        // DER, not the raw (r, s) concatenation: the server signs with
        // ECDSA_P256_SHA256_ASN1. See Ecdsa.verify's doc comment.
        return signature.derRepresentation.base64EncodedString()
    }

    static func rsaSign(enc: String, privateKey: _RSA.Signing.PrivateKey, padding: _RSA.Signing.Padding) -> String {
        let message = Data(enc.utf8)
        return RsaTestKey.sign(message, with: privateKey, padding: padding).base64EncodedString()
    }

    static func wrapInPEM(certificate: Certificate, beginMarker: String, endMarker: String) -> String {
        guard let json = try? JSONEncoder().encode(certificate) else {
            fatalError("CheckoutFixture.wrapInPEM: certificate encoding unexpectedly failed")
        }
        let body = json.base64EncodedString()
        return "\(beginMarker)\n\(body)\n\(endMarker)"
    }

    /// `wrapInPEM` pre-bound to `.lic` file markers, for `LicenseFileTests`'
    /// many call sites.
    static func wrapLicensePEM(enc: String, sig: String, alg: String) -> String {
        wrapInPEM(
            certificate: .init(enc: enc, sig: sig, alg: alg),
            beginMarker: "-----BEGIN LICENSE FILE-----", endMarker: "-----END LICENSE FILE-----"
        )
    }

    /// `wrapInPEM` pre-bound to `.machine` file markers, for
    /// `MachineFileTests`' many call sites.
    static func wrapMachinePEM(enc: String, sig: String, alg: String) -> String {
        wrapInPEM(
            certificate: .init(enc: enc, sig: sig, alg: alg),
            beginMarker: "-----BEGIN MACHINE FILE-----", endMarker: "-----END MACHINE FILE-----"
        )
    }

    /// A minimal, valid `{"data": {...}}` license-resource JSON payload.
    /// Format v2 puts the claims inside the signed bytes; a payload without
    /// them is a v1 file and no longer verifies. `exp` is omitted unless asked
    /// for, matching a checkout made without a `ttl`.
    static func licensePayloadJSON(
        key: String = "TEST-LICENSE-KEY",
        suspended: Bool = false,
        exp: Int64? = nil
    ) -> Data {
        let expField = exp.map { ",\"exp\":\($0)" } ?? ""
        let json = """
        {"data":{"id":"lic_123","type":"licenses","attributes":{"key":"\(key)","suspended":\(suspended),"uses":0}},\
        "meta":{"iat":1767225600,"jti":"test-jti","kid":"test-kid"\(expField)}}
        """
        return Data(json.utf8)
    }

    /// A `{"data": {...}}` license-resource payload exercising every field
    /// `License` models, including timestamps and metadata -- unlike
    /// `licensePayloadJSON` above, which omits them (they're all Optional,
    /// so a minimal fixture never exercises their decode path at all).
    static func fullLicensePayloadJSON(key: String = "TEST-LICENSE-KEY") -> Data {
        let json = """
        {"data":{"id":"lic_123","type":"licenses","attributes":{
          "key":"\(key)","suspended":false,"uses":3,
          "expiry":"2027-01-01T00:00:00Z",
          "last_validated_at":"2026-08-01T12:00:00.500Z",
          "last_check_in_at":"2026-07-15T09:30:00Z",
          "metadata":{"seats":5,"tier":"pro","trial":false,"note":null}
        }},
        "meta":{"iat":1767225600,"jti":"test-jti","kid":"test-kid"}}
        """
        return Data(json.utf8)
    }

    /// A minimal, valid `{"data": {...}, "meta": {...}}` machine-resource JSON
    /// payload.
    ///
    /// Format v2 puts the claims inside the signed bytes for machine files too
    /// -- `check_out_machine.rs` signs `{"data": <machine>, "meta": <claims>}`.
    /// `exp` is omitted unless asked for, matching a checkout made without a
    /// `ttl`, which the server genuinely allows.
    static func machinePayloadJSON(
        fingerprint: String = "fp-abc123",
        exp: Int64? = nil
    ) -> Data {
        let expField = exp.map { ",\"exp\":\($0)" } ?? ""
        let json = """
        {"data":{"id":"mach_123","type":"machines","attributes":{
          "fingerprint":"\(fingerprint)","heartbeat_status":"NOT_STARTED"
        }},
        "meta":{"iat":\(machineFixtureIat),"jti":"test-machine-jti","kid":"test-machine-kid"\(expField)}}
        """
        return Data(json.utf8)
    }

    /// The `iat` every `machinePayloadJSON` carries, so tests can express an
    /// `exp` relative to issue time instead of to a wall clock that moves.
    static let machineFixtureIat: Int64 = 1_767_225_600

    /// A machine payload with NO `meta` claims -- the shape a pre-v2 file had.
    /// Only reachable by an attacker who kept a v2 `alg` on a v1 payload, since
    /// `alg` is outside the signature.
    static func machinePayloadJSONWithoutClaims(fingerprint: String = "fp-abc123") -> Data {
        let json = """
        {"data":{"id":"mach_123","type":"machines","attributes":{
          "fingerprint":"\(fingerprint)","heartbeat_status":"NOT_STARTED"
        }}}
        """
        return Data(json.utf8)
    }
}
