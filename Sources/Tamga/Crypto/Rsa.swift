import CryptoExtras
import Foundation

/// RSA-2048 signature verification (PKCS#1 v1.5 and PSS, both SHA-256) via
/// swift-crypto's `_RSA.Signing`.
///
/// Used by `Checkout.MachineFile` (the PKCS1 and PSS branches of the
/// scheme-dispatched machine-file verifier) and `MachineProof` (offline proof
/// verification is ALWAYS RSA-2048 PKCS#1 v1.5 / SHA-256, regardless of the
/// license's scheme).
///
/// This used to go through the Security framework's `SecKey` API, which is
/// Apple-only and made the whole package impossible to compile on Linux.
/// `_CryptoExtras` covers both platforms with one code path. Keeping a single
/// implementation matters more than the underscore in the module name: a
/// per-platform split would be a second place for a verification bug to hide,
/// and this SDK family's audit already found the same curve-confusion class
/// independently present in 3 of 5 reimplementations.
enum Rsa {
    /// The only modulus size the server issues, and the only one accepted here.
    static let requiredKeySizeInBits = 2048

    /// Imports an RSA public key from DER bytes, rejecting anything that is
    /// not exactly 2048 bits.
    ///
    /// BOTH PKCS#1 `RSAPublicKey` and X.509 `SubjectPublicKeyInfo` are
    /// accepted, because `_RSA.Signing.PublicKey(derRepresentation:)` accepts
    /// both and the server publishes the former: `extract_public_key`
    /// (`license_signing.rs`) and `key_material.rs` both return whatever
    /// aws-lc-rs's `RsaKeyPair::public_key().as_der()` yields, which is PKCS#1.
    /// Confirmed empirically against server-issued fixtures: 270 bytes opening
    /// `30 82 01 0a 02 82 01 01 00`, parsing to 2048 bits, verifying real
    /// signatures. This function used to be documented as SPKI-only, which was
    /// simply wrong about what it accepted; no behaviour changed with the
    /// correction. Contrast `Ecdsa`, where the equivalent mismatch WAS real and
    /// did need a fix.
    ///
    /// SECURITY: the size check is the point of this function existing rather
    /// than the initializer being called inline. `_RSA.Signing.PublicKey`
    /// happily accepts a 512- or 1024-bit key, and a signature made with one
    /// verifies correctly -- it is simply far cheaper to forge. Since the key
    /// reaching here can come from a caller-supplied file, "verifies" must
    /// also mean "at the strength this protocol requires". Mirrors the same
    /// explicit check in `tamga-java`'s `Rsa.java`.
    private static func importPublicKey(fromDER der: Data) -> _RSA.Signing.PublicKey? {
        guard let key = try? _RSA.Signing.PublicKey(derRepresentation: der) else {
            return nil
        }
        guard key.keySizeInBits == requiredKeySizeInBits else {
            return nil
        }
        return key
    }

    /// Verifies an RSA-PKCS#1 v1.5/SHA-256 signature.
    static func verifyPkcs1(publicKeyDER: Data, message: Data, signature: Data) -> Bool {
        verify(publicKeyDER: publicKeyDER, message: message, signature: signature,
               padding: .insecurePKCS1v1_5)
    }

    /// Verifies an RSA-PSS/SHA-256 signature.
    static func verifyPss(publicKeyDER: Data, message: Data, signature: Data) -> Bool {
        verify(publicKeyDER: publicKeyDER, message: message, signature: signature,
               padding: .PSS)
    }

    private static func verify(
        publicKeyDER: Data,
        message: Data,
        signature: Data,
        padding: _RSA.Signing.Padding
    ) -> Bool {
        guard let key = importPublicKey(fromDER: publicKeyDER) else {
            return false
        }
        // Fails closed: a malformed key, a wrong-sized key, a malformed
        // signature and a genuine verification failure all land on `false`,
        // which is the behaviour every caller of this type relies on.
        return key.isValidSignature(
            _RSA.Signing.RSASignature(rawRepresentation: signature),
            for: message,
            padding: padding
        )
    }
}
