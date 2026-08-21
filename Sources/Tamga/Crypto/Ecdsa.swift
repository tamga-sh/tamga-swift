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
    /// The length of an uncompressed X9.63 P-256 point: a `0x04` prefix plus a
    /// 32-byte X and a 32-byte Y coordinate.
    private static let uncompressedPointLength = 65

    /// - Parameter publicKey: either an X.509 `SubjectPublicKeyInfo`-encoded
    ///   P-256 key, or a bare 65-byte uncompressed X9.63 point.
    ///
    /// BOTH encodings are accepted because the server publishes the bare
    /// point. `key_material.rs` stores `ecdsa_public_key` as
    /// `BASE64.encode(ecdsa_pair.public_key().as_ref())`, which aws-lc-rs
    /// returns as the uncompressed point -- pinned server-side by its own
    /// `ecdsa_public_key_is_65_bytes` test -- and `accounts/serializer.rs`
    /// hands that same string to API callers. Accepting only SPKI meant this
    /// SDK could not verify ANY genuine ECDSA machine file: a caller who
    /// base64-decoded the key the API gave them got `false` from every call.
    /// Confirmed empirically against server-issued fixtures.
    ///
    /// SECURITY -- the curve check, and why the two paths differ. An SPKI
    /// carries a self-declared curve OID, so it is checked against P-256
    /// explicitly before the key is trusted. Confirmed directly (empirically,
    /// not assumed): CryptoKit's `P256.Signing.PublicKey(derRepresentation:)`
    /// does NOT validate that OID -- only the resulting coordinate byte
    /// length. A hand-crafted SPKI declaring the secp256k1 curve OID but
    /// carrying a real P-256 point's raw coordinates (same 65-byte length) was
    /// silently accepted. Without this guard, a validly-signed message from a
    /// different, same-coordinate-size curve would verify successfully -- the
    /// exact curve-confusion bug class this SDK family's own audit found live
    /// in tamga-python/go/dotnet's generic `ECDsa`-based verifiers.
    ///
    /// A bare point declares no curve at all, so there is nothing to confuse
    /// it with: the curve comes from the caller's own `EcdsaP256Sign` scheme,
    /// and `P256.Signing.PublicKey(x963Representation:)` rejects any point
    /// that does not lie on P-256 (verified against both a corrupted
    /// coordinate and a real P-384 point). Do not "unify" the two branches by
    /// dropping the OID check on the SPKI path -- see `DER.swift` for the
    /// extractor it relies on, and `EcdsaTests.swift`'s
    /// `verify_returnsFalse_whenKeyIsNotP256Curve` for the regression coverage
    /// (a real P384/secp256k1 key, not a mock).
    static func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard let key = importPublicKey(publicKey),
              let ecdsaSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
        else {
            return false
        }

        return key.isValidSignature(ecdsaSignature, for: message)
    }

    /// Fails closed: an unrecognised encoding, a non-P-256 curve OID, and a
    /// point that is not on the curve all return `nil`.
    private static func importPublicKey(_ publicKey: Data) -> P256.Signing.PublicKey? {
        if publicKey.count == uncompressedPointLength {
            return try? P256.Signing.PublicKey(x963Representation: publicKey)
        }

        guard let curveOID = DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: publicKey),
              curveOID == p256CurveOID
        else {
            return nil
        }
        return try? P256.Signing.PublicKey(derRepresentation: publicKey)
    }
}
