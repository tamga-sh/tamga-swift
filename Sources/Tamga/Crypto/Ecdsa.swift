import CryptoKit
import Foundation

/// ECDSA P-256/SHA-256 signature verification via CryptoKit's `P256.Signing`
/// (native since iOS 13 / macOS 10.15, no third-party dependency).
///
/// Used by `Checkout.MachineFile` -- the ECDSA-P256 branch of the
/// scheme-dispatched machine-file verifier.
enum Ecdsa {
    /// NIST P-256 (secp256r1/prime256v1) named-curve OID -- 1.2.840.10045.3.1.7
    /// -- as raw DER OID content bytes (no tag/length prefix).
    private static let p256CurveOID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

    /// Verifies an ECDSA P-256/SHA-256 signature over raw `(r, s)`
    /// concatenated bytes (the IEEE P1363 wire format this scheme uses, as
    /// opposed to DER-encoded ASN.1).
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
              let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else {
            return false
        }

        return key.isValidSignature(ecdsaSignature, for: message)
    }
}
