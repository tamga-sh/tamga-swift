import Foundation

/// AES-256-GCM open logic shared by `LicenseFile` and `MachineFile`.
///
/// The two file types genuinely differ in how the sealed bytes are framed, and
/// the difference is not cosmetic -- it is why every SDK in this fleet failed
/// to open an encrypted machine file:
///
/// | file | `enc` when encrypted | server source |
/// |---|---|---|
/// | `.lic` | `base64(nonce ‖ ciphertext ‖ tag)` | `license_file.rs` `aes256gcm_encrypt` |
/// | `.machine` | `"<nonce_b64>.<cipher_b64>"` | `field_encryption.rs` `FieldEncryption::encrypt` |
///
/// so `decryptConcatenated` serves license files and `decryptDotSeparated`
/// serves machine files. Only the `Hkdf` derivation that produced `key` differs
/// beyond that (see each type's own remarks), so that key is the only other
/// thing callers supply.
enum EncryptedPayloadDecryptor {
    /// Opens a single blob framed as `nonce ‖ ciphertext ‖ tag`.
    ///
    /// This is the LICENSE file framing. Do not reach for it from the machine
    /// file path: slicing a nonce off the first 12 bytes of a machine file's
    /// `enc` produces a nonce made of the first 9 bytes of the real nonce's
    /// base64 text, and there is no key under which that opens.
    static func decryptConcatenated(_ payloadBytes: Data, key: Data, context: String) throws -> Data {
        let minLength = AesGcmCipher.nonceLength + AesGcmCipher.tagLength
        guard payloadBytes.count >= minLength else {
            throw TamgaCheckoutError.offlineFileFormat(
                "\(context) payload too short: expected at least \(minLength) bytes, got \(payloadBytes.count)."
            )
        }

        let nonce = payloadBytes.prefix(AesGcmCipher.nonceLength)
        let tag = payloadBytes.suffix(AesGcmCipher.tagLength)
        let ciphertext = payloadBytes.dropFirst(AesGcmCipher.nonceLength).dropLast(AesGcmCipher.tagLength)

        return try open(key: key, nonce: nonce, ciphertext: ciphertext, tag: tag, context: context)
    }

    /// Opens a machine file's `"<nonce_b64>.<cipher_b64>"` framing.
    ///
    /// The two halves are base64-encoded SEPARATELY, so the whole string is not
    /// itself valid base64 -- `.` is not in the alphabet. Decode each half on
    /// its own; concatenating them first, or decoding the whole string, cannot
    /// work.
    ///
    /// `cipher_b64` already carries the 16-byte GCM tag appended to the
    /// ciphertext (`seal_in_place_append_tag` server-side), so the tag is split
    /// off this half, never off the nonce half.
    ///
    /// - Parameter enc: the RAW `enc` string. Callers must have verified the
    ///   signature over these exact bytes already -- this function is the first
    ///   thing in the pipeline that interprets attacker-supplied structure.
    static func decryptDotSeparated(_ enc: String, key: Data, context: String) throws -> Data {
        // `omittingEmptySubsequences: false` so `".x"`, `"x."` and `"."` are
        // seen as the malformed 2-part inputs they are rather than collapsing
        // into a 1-part success path. `maxSplits` is unbounded on purpose: a
        // third `.` means the framing is not what the server emits, and the
        // count check below rejects it instead of silently keeping a prefix.
        let halves = enc.split(separator: ".", omittingEmptySubsequences: false)
        guard halves.count == 2 else {
            throw TamgaCheckoutError.offlineFileFormat(
                "\(context) 'enc' is not the expected '<nonce_b64>.<cipher_b64>' pair " +
                "(found \(halves.count) dot-separated part(s))."
            )
        }

        guard let nonce = Data(base64Encoded: String(halves[0])),
              let ciphertextAndTag = Data(base64Encoded: String(halves[1]))
        else {
            throw TamgaCheckoutError.offlineFileFormat(
                "\(context) 'enc' halves are not both valid base64."
            )
        }

        guard nonce.count == AesGcmCipher.nonceLength else {
            throw TamgaCheckoutError.offlineFileFormat(
                "\(context) nonce is \(nonce.count) bytes, expected \(AesGcmCipher.nonceLength)."
            )
        }
        guard ciphertextAndTag.count >= AesGcmCipher.tagLength else {
            throw TamgaCheckoutError.offlineFileFormat(
                "\(context) ciphertext is shorter than the \(AesGcmCipher.tagLength)-byte GCM tag it must contain."
            )
        }

        let tag = ciphertextAndTag.suffix(AesGcmCipher.tagLength)
        let ciphertext = ciphertextAndTag.dropLast(AesGcmCipher.tagLength)

        return try open(key: key, nonce: nonce, ciphertext: ciphertext, tag: tag, context: context)
    }

    /// Fails closed, and collapses every AES-GCM failure onto one message: a
    /// caller holding the file already knows which key and fingerprint it
    /// passed, so there is nothing to gain from distinguishing them here.
    private static func open(key: Data, nonce: Data, ciphertext: Data, tag: Data, context: String) throws -> Data {
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
