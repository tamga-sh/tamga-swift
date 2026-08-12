import CryptoKit
import Foundation

/// AES-256-GCM open/seal wrapper over CryptoKit's `AES.GCM` (native since
/// iOS 13 / macOS 10.15, no third-party dependency). Algorithm-only: never
/// derives the AES key itself -- see `NaiveKey` (license checkout) and
/// `Hkdf` (machine checkout) for the two distinct, non-interchangeable
/// key-derivation paths that feed this type.
enum AesGcmCipher {
    /// Standard AES-GCM nonce length in bytes.
    static let nonceLength = 12
    /// Standard AES-GCM authentication tag length in bytes.
    static let tagLength = 16

    /// Named `CipherError`, not `OpenError` -- shared by both `open` and
    /// `seal`, not just the decrypt direction.
    enum CipherError: Error {
        /// Authentication failed -- wrong key, wrong nonce, or a tampered
        /// ciphertext/tag. Fails closed: never returns garbage plaintext for
        /// a tampered input.
        case authenticationFailed
        /// The nonce, tag, or sealed-box construction itself was
        /// structurally invalid (e.g. wrong-length nonce/tag, or `seal`
        /// rejecting the key/nonce before encryption even runs) --
        /// distinguishable from `authenticationFailed` since it means the
        /// caller passed malformed input, not that CryptoKit
        /// cryptographically rejected a well-formed one.
        case malformedInput
    }

    /// Decrypts and authenticates a ciphertext. Throws `CipherError.authenticationFailed`
    /// (fails closed) on tag mismatch -- never returns garbage plaintext for
    /// a tampered input.
    static func open(key: Data, nonce: Data, ciphertext: Data, tag: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        guard let gcmNonce = try? AES.GCM.Nonce(data: nonce) else {
            throw CipherError.malformedInput
        }
        guard let sealedBox = try? AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag) else {
            throw CipherError.malformedInput
        }
        do {
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw CipherError.authenticationFailed
        }
    }

    /// Encrypts and authenticates a plaintext, producing ciphertext and a
    /// separate authentication tag. Any failure -- including CryptoKit's own
    /// (e.g. a wrong-length key) -- surfaces as `CipherError.malformedInput`,
    /// never a raw, untranslated CryptoKit error type.
    static func seal(key: Data, nonce: Data, plaintext: Data) throws -> (ciphertext: Data, tag: Data) {
        let symmetricKey = SymmetricKey(data: key)
        guard let gcmNonce = try? AES.GCM.Nonce(data: nonce) else {
            throw CipherError.malformedInput
        }
        guard let sealedBox = try? AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce) else {
            throw CipherError.malformedInput
        }
        return (sealedBox.ciphertext, sealedBox.tag)
    }
}
