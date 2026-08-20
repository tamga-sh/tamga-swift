import Crypto
import Foundation

/// ECDSA P-256/SHA-256 signature verification via swift-crypto's `P256.Signing`,
/// which forwards to CryptoKit on Apple platforms and to BoringSSL on Linux.
///
/// Used by `Checkout.MachineFile` -- the ECDSA-P256 branch of the
/// scheme-dispatched machine-file verifier.
enum Ecdsa {
    /// NIST P-256 (secp256r1/prime256v1) named-curve OID -- 1.2.840.10045.3.1.7
    /// -- as raw DER OID content bytes (no tag/length prefix).
    private static let p256CurveOID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

    /// Verifies an ECDSA P-256/SHA-256 signature encoded as ASN.1 DER.
    ///
    /// CRITICAL: the signature is DER, NOT the raw `(r, s)` IEEE P1363
    /// concatenation. The server signs with `ECDSA_P256_SHA256_ASN1`, and
    /// every other SDK in the fleet decodes it that way -- `tamga-go` uses
    /// `ecdsa.VerifyASN1`, `tamga-rust` uses `ECDSA_P256_SHA256_ASN1`, and
    /// `tamga-js` passes `{ format: "der" }`. Confirmed against a real
    /// checked-out fixture: the signature is 71 bytes beginning with `0x30`
    /// (a DER SEQUENCE), where a P1363 signature would be exactly 64 raw
    /// bytes. This previously used `rawRepresentation`, which rejected every
    /// genuine server-issued ECDSA machine file.
    ///
    /// - Parameter publicKeyDER: an X.509 `SubjectPublicKeyInfo`-encoded public key.
    ///
    /// SECURITY: `publicKeyDER`'s declared curve is checked against P-256
    /// explicitly before the key is trusted. Confirmed directly (empirically,
    /// not assumed): CryptoKit's `P256.Signing.PublicKey(derRepresentation:)`
    /// does NOT validate the curve OID in the SPKI it parses -- only the
    /// resulting coordinate byte length. A hand-crafted SPKI declaring the
    /// secp256k1 curve OID but carrying a real P-256 point's raw coordinates
    /// (same 65-byte length) was silently accepted. Without this guard, a
    /// validly-signed message from a different, same-coordinate-size curve
    /// would verify successfully -- the exact curve-confusion bug class this
    /// SDK family's own audit found live in tamga-python/go/dotnet's generic
    /// `ECDsa`-based verifiers, which had no equivalent check. See
    /// `DER.swift` for the OID-extraction helper this relies on, and
    /// `EcdsaTests.swift`'s `verify_returnsFalse_whenKeyIsNotP256Curve` for
    /// the regression coverage (uses a real P384/secp256k1 key, not a mock).
    static func verify(publicKeyDER: Data, message: Data, signature: Data) -> Bool {
        guard let curveOID = DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: publicKeyDER),
              curveOID == p256CurveOID
        else {
            return false
        }

        guard let key = try? P256.Signing.PublicKey(derRepresentation: publicKeyDER),
              let ecdsaSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
        else {
            return false
        }

        return key.isValidSignature(ecdsaSignature, for: message)
    }
}
