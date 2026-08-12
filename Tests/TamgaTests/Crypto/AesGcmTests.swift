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

        #expect(throws: AesGcmCipher.OpenError.authenticationFailed) {
            try AesGcmCipher.open(key: key, nonce: nonce, ciphertext: tampered, tag: tag)
        }
    }

    @Test("open throws authenticationFailed for the wrong key")
    func openThrowsForWrongKey() throws {
        let key = Self.randomBytes(32)
        let wrongKey = Self.randomBytes(32)
        let nonce = Self.randomBytes(AesGcmCipher.nonceLength)
        let (ciphertext, tag) = try AesGcmCipher.seal(key: key, nonce: nonce, plaintext: Data("payload".utf8))

        #expect(throws: AesGcmCipher.OpenError.authenticationFailed) {
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

        #expect(throws: AesGcmCipher.OpenError.authenticationFailed) {
            try AesGcmCipher.open(key: key, nonce: nonce, ciphertext: ciphertext, tag: tamperedTag)
        }
    }
}
