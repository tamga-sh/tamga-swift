import Foundation

/// Shared `nonce || ciphertext || tag` slicing + AES-256-GCM open logic for
/// `LicenseFile` and `MachineFile` -- the two types are identical here except
/// for which `Hkdf` derivation produced `key` (see that type's own
/// remarks), so that key is the only thing callers supply.
enum EncryptedPayloadDecryptor {
    static func decrypt(_ payloadBytes: Data, key: Data, context: String) throws -> Data {
        let minLength = AesGcmCipher.nonceLength + AesGcmCipher.tagLength
        guard payloadBytes.count >= minLength else {
            throw TamgaCheckoutError.offlineFileFormat(
                "\(context) payload too short: expected at least \(minLength) bytes, got \(payloadBytes.count)."
            )
        }

        let nonce = payloadBytes.prefix(AesGcmCipher.nonceLength)
        let tag = payloadBytes.suffix(AesGcmCipher.tagLength)
        let ciphertext = payloadBytes.dropFirst(AesGcmCipher.nonceLength).dropLast(AesGcmCipher.tagLength)

        do {
            return try AesGcmCipher.open(key: key, nonce: nonce, ciphertext: ciphertext, tag: tag)
        } catch {
            throw TamgaCheckoutError.decryptionFailed(
                "\(context) failed to decrypt -- verify the license key (and fingerprint, for machine files) " +
                "are correct, or the file may be corrupted."
            )
        }
    }
}
