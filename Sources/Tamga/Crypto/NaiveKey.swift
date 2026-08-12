import Foundation

/// License-checkout's encryption key derivation, replicated exactly as the
/// server does it (`tamga-api/src/features/licenses/check_out_license.rs`).
///
/// CRITICAL: not a KDF and not a hash. It is the license key's raw UTF-8
/// bytes, zero-padded (keys shorter than 32 bytes) or truncated (keys longer
/// than 32 bytes) to exactly 32 bytes. A verifier that hashes the key
/// instead of zero-pad/truncating will silently fail to decrypt every
/// encrypted `.lic` file.
///
/// Contrast with `Hkdf` (machine checkout), which IS a real KDF
/// (HKDF-SHA256) and additionally binds the machine's fingerprint into the
/// derivation -- the two paths are not interchangeable.
enum NaiveKey {
    /// The fixed AES-256 key length this derivation always produces.
    static let keyLength = 32

    /// Derives the 32-byte AES key from a license key string. CRITICAL: not
    /// a KDF -- see type-level remarks. Zero-pads short keys, truncates long
    /// keys; never hashes.
    static func derive(licenseKey: String) -> Data {
        var keyBytes = Array(Data(licenseKey.utf8))
        if keyBytes.count < keyLength {
            keyBytes.append(contentsOf: repeatElement(0, count: keyLength - keyBytes.count))
        } else if keyBytes.count > keyLength {
            keyBytes = Array(keyBytes.prefix(keyLength))
        }
        return Data(keyBytes)
    }
}
