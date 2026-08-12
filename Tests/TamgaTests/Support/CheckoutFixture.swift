import CryptoKit
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
        let (ciphertext, tag) = try! AesGcmCipher.seal(key: key, nonce: nonce, plaintext: json)
        var combined = nonce
        combined.append(ciphertext)
        combined.append(tag)
        return combined.base64EncodedString()
    }

    /// Signs `enc`'s base64 STRING bytes (not decoded bytes) with an Ed25519
    /// key, matching the real wire contract.
    static func ed25519Sign(enc: String, privateKey: Curve25519.Signing.PrivateKey) -> String {
        let message = Data(enc.utf8)
        let signature = try! privateKey.signature(for: message)
        return signature.base64EncodedString()
    }

    static func ecdsaSign(enc: String, privateKey: P256.Signing.PrivateKey) -> String {
        let message = Data(enc.utf8)
        let signature = try! privateKey.signature(for: message)
        return signature.rawRepresentation.base64EncodedString()
    }

    static func rsaSign(enc: String, privateKey: SecKey, algorithm: SecKeyAlgorithm) -> String {
        let message = Data(enc.utf8)
        return RsaTestKey.sign(message, with: privateKey, algorithm: algorithm).base64EncodedString()
    }

    static func wrapInPEM(certificate: Certificate, beginMarker: String, endMarker: String) -> String {
        let json = try! JSONEncoder().encode(certificate)
        let body = json.base64EncodedString()
        return "\(beginMarker)\n\(body)\n\(endMarker)"
    }

    /// A minimal, valid `{"data": {...}}` license-resource JSON payload.
    static func licensePayloadJSON(key: String = "TEST-LICENSE-KEY", suspended: Bool = false) -> Data {
        let json = """
        {"data":{"id":"lic_123","type":"licenses","attributes":{"key":"\(key)","suspended":\(suspended),"uses":0}}}
        """
        return Data(json.utf8)
    }

    /// A minimal, valid `{"data": {...}}` machine-resource JSON payload.
    static func machinePayloadJSON(fingerprint: String = "fp-abc123") -> Data {
        let json = """
        {"data":{"id":"mach_123","type":"machines","attributes":{"fingerprint":"\(fingerprint)","heartbeat_status":"NOT_STARTED"}}}
        """
        return Data(json.utf8)
    }
}
