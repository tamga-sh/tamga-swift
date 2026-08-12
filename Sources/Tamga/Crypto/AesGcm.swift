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

    enum OpenError: Error {
        /// Authentication failed -- wrong key, wrong nonce, or a tampered
        /// ciphertext/tag. Fails closed: never returns garbage plaintext for
        /// a tampered input.
        case authenticationFailed
        case malformedInput
    }

    /// Decrypts and authenticates a ciphertext. Throws `OpenError.authenticationFailed`
    /// (fails closed) on tag mismatch -- never returns garbage plaintext for
    /// a tampered input.
    static func open(key: Data, nonce: Data, ciphertext: Data, tag: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        guard let gcmNonce = try? AES.GCM.Nonce(data: nonce) else {
            throw OpenError.malformedInput
        }
        guard let sealedBox = try? AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag) else {
            throw OpenError.malformedInput
        }
        do {
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw OpenError.authenticationFailed
        }
    }

    /// Encrypts and authenticates a plaintext, producing ciphertext and a
    /// separate authentication tag.
    static func seal(key: Data, nonce: Data, plaintext: Data) throws -> (ciphertext: Data, tag: Data) {
        let symmetricKey = SymmetricKey(data: key)
        guard let gcmNonce = try? AES.GCM.Nonce(data: nonce) else {
            throw OpenError.malformedInput
        }
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce)
        return (sealedBox.ciphertext, sealedBox.tag)
    }
}
