import CryptoKit
import Foundation

/// HKDF-SHA256 wrapper (RFC 5869) via CryptoKit's `HKDF<SHA256>` (native
/// since iOS 13 / macOS 10.15, no third-party dependency). Machine
/// checkout's real, properly-derived encryption key: 32 bytes from
/// `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`,
/// `info = <machine fingerprint>`.
///
/// GOTCHA: this is the machine-checkout key derivation and is a REAL KDF --
/// explicitly NOT the same scheme as license checkout's naive derivation
/// (see `NaiveKey`). Machine file decryption requires BOTH the license key
/// AND the target machine's fingerprint; license file decryption requires
/// only the license key. Do not conflate the two paths -- "unifying" them
/// would silently break interop with whichever format wasn't matched.
enum Hkdf {
    /// Fixed salt for machine-file key derivation, matching the server exactly.
    static let salt = Data("tamga:machine-file-key-v1".utf8)

    /// The fixed AES-256 key length this derivation always produces.
    static let keyLength = 32

    /// Derives the 32-byte AES key from the license key (as IKM) and machine
    /// fingerprint (as info).
    static func deriveMachineFileKey(licenseKey: String, fingerprint: String) -> Data {
        let ikm = SymmetricKey(data: Data(licenseKey.utf8))
        let info = Data(fingerprint.utf8)
        let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: info, outputByteCount: keyLength)
        return derived.withUnsafeBytes { Data($0) }
    }
}
