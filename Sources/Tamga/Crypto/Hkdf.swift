import CryptoKit
import Foundation

/// HKDF-SHA256 wrapper (RFC 5869) via CryptoKit's `HKDF<SHA256>` (native
/// since iOS 13 / macOS 10.15, no third-party dependency). Machine
/// checkout's real, properly-derived encryption key: 32 bytes from
/// `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`,
/// `info = <machine fingerprint>`.
///
/// Both offline file formats derive their AES key here as of format v2, but
/// with different parameters -- do not conflate the two paths. Machine file
/// decryption requires BOTH the license key AND the target machine's
/// fingerprint, so a machine file cannot be opened anywhere but on the machine
/// it was issued for; a license file is not bound to a machine.
///
/// Before v2 the license-file key was not derived at all: it was the license
/// key's raw UTF-8 bytes zero-padded to 32, which meant an attacker holding a
/// stolen `.lic` was attacking the license key's own entropy rather than a
/// 256-bit key space. The `NaiveKey` type that implemented it has been removed
/// rather than deprecated -- leaving it available would let a caller silently
/// keep using the weaker derivation.
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

    /// Fixed salt for license-file key derivation, matching the server exactly.
    static let licenseFileSalt = Data("tamga:license-file-key-v1".utf8)

    /// Fixed `info` for license-file key derivation.
    static let licenseFileInfo = Data("license-file".utf8)

    /// Derives the 32-byte AES key for an encrypted `.lic` file:
    /// `salt = "tamga:license-file-key-v1"`, `ikm = licenseKey`,
    /// `info = "license-file"`. No fingerprint -- a license file is not bound
    /// to a machine.
    static func deriveLicenseFileKey(licenseKey: String) -> Data {
        let ikm = SymmetricKey(data: Data(licenseKey.utf8))
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: licenseFileSalt,
            info: licenseFileInfo,
            outputByteCount: keyLength
        )
        return derived.withUnsafeBytes { Data($0) }
    }
}
