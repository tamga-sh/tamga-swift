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
    /// than the initializer being called inline, and it is an equality check
    /// rather than a floor on purpose -- 2048 is the only size the server
    /// issues, so anything else means the key did not come from where the
    /// caller thinks it did.
    ///
    /// Be precise about what the initializer does and does not do for you,
    /// because the wrong version of this note would invite deleting the guard.
    /// Measured against the pinned swift-crypto 4.5.1: it REJECTS a 1024-bit
    /// key on its own (so the classic "a weak key still verifies, it is just
    /// cheap to forge" framing is not what is being defended against here),
    /// but it ACCEPTS 3072- and 4096-bit keys. Those are the cases this guard
    /// actually rejects. Do not relax it to `>= 2048` on the theory that a
    /// bigger key is harmless: the point is that the key material matches the
    /// account's published key, and a size the server cannot have issued is a
    /// signal, not a convenience. Mirrors the same explicit check in
    /// `tamga-java`'s `Rsa.java`.
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
