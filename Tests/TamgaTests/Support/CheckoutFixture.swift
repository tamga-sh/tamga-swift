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

    /// Builds a base64 `enc` payload for an AES-256-GCM-encrypted file:
    /// base64 of `nonce || ciphertext || tag`.
    static func encryptedEnc(json: Data, key: Data) -> String {
        let nonce = Data((0..<AesGcmCipher.nonceLength).map { _ in UInt8.random(in: .min ... .max) })
        guard let (ciphertext, tag) = try? AesGcmCipher.seal(key: key, nonce: nonce, plaintext: json) else {
            fatalError("CheckoutFixture.encryptedEnc: AES-GCM seal unexpectedly failed")
        }
        var combined = nonce
        combined.append(ciphertext)
        combined.append(tag)
        return combined.base64EncodedString()
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

    /// A minimal, valid `{"data": {...}}` machine-resource JSON payload.
    static func machinePayloadJSON(fingerprint: String = "fp-abc123") -> Data {
        let json = """
        {"data":{"id":"mach_123","type":"machines","attributes":{
          "fingerprint":"\(fingerprint)","heartbeat_status":"NOT_STARTED"
        }}}
        """
        return Data(json.utf8)
    }
}
