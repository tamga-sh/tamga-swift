import Foundation
import Testing

@testable import Tamga

@Suite("AesGcmCipher")
struct AesGcmTests {
    private static func randomBytes(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
    }

    @Test("seal then open round-trips the plaintext")
    func sealThenOpenRoundTrips() throws {
        let key = Self.randomBytes(32)
        let nonce = Self.randomBytes(AesGcmCipher.nonceLength)
        let plaintext = Data("license file plaintext payload".utf8)

        let (ciphertext, tag) = try AesGcmCipher.seal(key: key, nonce: nonce, plaintext: plaintext)
        let opened = try AesGcmCipher.open(key: key, nonce: nonce, ciphertext: ciphertext, tag: tag)

        #expect(opened == plaintext)
    }

    @Test("open throws authenticationFailed for a tampered ciphertext")
    func openThrowsForTamperedCiphertext() throws {
        let key = Self.randomBytes(32)
        let nonce = Self.randomBytes(AesGcmCipher.nonceLength)
        let (ciphertext, tag) = try AesGcmCipher.seal(key: key, nonce: nonce, plaintext: Data("payload".utf8))

        // NOTE: mutate at .startIndex, never a literal 0 -- confirmed
        // directly that AES.GCM.SealedBox.ciphertext's Data is a slice view
        // into the box's combined (nonce+ciphertext+tag) buffer, so its
        // startIndex is the nonce length (12), not 0. Subscripting with a
        // literal 0 is out of bounds and traps.
        var tampered = ciphertext
        tampered[tampered.startIndex] ^= 0xFF

        #expect(throws: AesGcmCipher.CipherError.authenticationFailed) {
            try AesGcmCipher.open(key: key, nonce: nonce, ciphertext: tampered, tag: tag)
        }
    }

    @Test("open throws authenticationFailed for the wrong key")
    func openThrowsForWrongKey() throws {
        let key = Self.randomBytes(32)
        let wrongKey = Self.randomBytes(32)
        let nonce = Self.randomBytes(AesGcmCipher.nonceLength)
        let (ciphertext, tag) = try AesGcmCipher.seal(key: key, nonce: nonce, plaintext: Data("payload".utf8))

        #expect(throws: AesGcmCipher.CipherError.authenticationFailed) {
            try AesGcmCipher.open(key: wrongKey, nonce: nonce, ciphertext: ciphertext, tag: tag)
        }
    }

    @Test("open throws authenticationFailed for a tampered tag")
    func openThrowsForTamperedTag() throws {
        let key = Self.randomBytes(32)
        let nonce = Self.randomBytes(AesGcmCipher.nonceLength)
        let (ciphertext, tag) = try AesGcmCipher.seal(key: key, nonce: nonce, plaintext: Data("payload".utf8))

        var tamperedTag = tag
        tamperedTag[tamperedTag.startIndex] ^= 0xFF

        #expect(throws: AesGcmCipher.CipherError.authenticationFailed) {
            try AesGcmCipher.open(key: key, nonce: nonce, ciphertext: ciphertext, tag: tamperedTag)
        }
    }

    // MARK: - malformedInput (distinct from authenticationFailed -- structurally
    // invalid input, not a cryptographically-rejected well-formed one).
    // Thresholds below confirmed empirically against real CryptoKit: a nonce
    // under 12 bytes is rejected by `AES.GCM.Nonce(data:)`, a tag other than
    // exactly 16 bytes is rejected by `AES.GCM.SealedBox`'s init, and a key
    // outside {16, 24, 32} bytes is rejected by `AES.GCM.seal` itself.

    @Test("open throws malformedInput for a too-short nonce")
    func openThrowsMalformedInputForShortNonce() {
        let key = Self.randomBytes(32)
        let shortNonce = Self.randomBytes(8)
        let ciphertext = Self.randomBytes(16)
        let tag = Self.randomBytes(AesGcmCipher.tagLength)

        #expect(throws: AesGcmCipher.CipherError.malformedInput) {
            try AesGcmCipher.open(key: key, nonce: shortNonce, ciphertext: ciphertext, tag: tag)
        }
    }

    @Test("open throws malformedInput for a wrong-length tag")
    func openThrowsMalformedInputForWrongLengthTag() {
        let key = Self.randomBytes(32)
        let nonce = Self.randomBytes(AesGcmCipher.nonceLength)
        let ciphertext = Self.randomBytes(16)
        let wrongLengthTag = Self.randomBytes(8)

        #expect(throws: AesGcmCipher.CipherError.malformedInput) {
            try AesGcmCipher.open(key: key, nonce: nonce, ciphertext: ciphertext, tag: wrongLengthTag)
        }
    }

    @Test("seal throws malformedInput for a too-short nonce")
    func sealThrowsMalformedInputForShortNonce() {
        let key = Self.randomBytes(32)
        let shortNonce = Self.randomBytes(8)

        #expect(throws: AesGcmCipher.CipherError.malformedInput) {
            try AesGcmCipher.seal(key: key, nonce: shortNonce, plaintext: Data("payload".utf8))
        }
    }

    @Test("seal throws malformedInput for a wrong-length key")
    func sealThrowsMalformedInputForWrongLengthKey() {
        let wrongLengthKey = Self.randomBytes(31)
        let nonce = Self.randomBytes(AesGcmCipher.nonceLength)

        #expect(throws: AesGcmCipher.CipherError.malformedInput) {
            try AesGcmCipher.seal(key: wrongLengthKey, nonce: nonce, plaintext: Data("payload".utf8))
        }
    }
}
