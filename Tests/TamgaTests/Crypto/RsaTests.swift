import Foundation
import _CryptoExtras
import Testing

@testable import Tamga

@Suite("Rsa")
struct RsaTests {
    @Test("verifyPkcs1 returns true for a valid PKCS#1 v1.5 signature")
    func verifyPkcs1ReturnsTrueForValidSignature() {
        let pair = RsaTestKey.generate()
        let message = Data("machine file payload".utf8)
        let signature = RsaTestKey.sign(message, with: pair.privateKey, padding: .insecurePKCS1v1_5)

        #expect(Rsa.verifyPkcs1(publicKeyDER: pair.publicKeySPKI, message: message, signature: signature))
    }

    @Test("verifyPss returns true for a valid PSS signature")
    func verifyPssReturnsTrueForValidSignature() {
        let pair = RsaTestKey.generate()
        let message = Data("machine file payload".utf8)
        let signature = RsaTestKey.sign(message, with: pair.privateKey, padding: .PSS)

        #expect(Rsa.verifyPss(publicKeyDER: pair.publicKeySPKI, message: message, signature: signature))
    }

    @Test("verifyPkcs1 returns false for a tampered message")
    func verifyPkcs1ReturnsFalseForTamperedMessage() {
        let pair = RsaTestKey.generate()
        let original = Data("original".utf8)
        let signature = RsaTestKey.sign(original, with: pair.privateKey, padding: .insecurePKCS1v1_5)

        let tampered = Data("tampered".utf8)
        #expect(!Rsa.verifyPkcs1(publicKeyDER: pair.publicKeySPKI, message: tampered, signature: signature))
    }

    @Test("verifyPkcs1 does not accept a PSS signature (padding schemes are not interchangeable)")
    func verifyPkcs1RejectsPssSignature() {
        let pair = RsaTestKey.generate()
        let message = Data("machine file payload".utf8)
        let pssSignature = RsaTestKey.sign(message, with: pair.privateKey, padding: .PSS)

        #expect(!Rsa.verifyPkcs1(publicKeyDER: pair.publicKeySPKI, message: message, signature: pssSignature))
    }

    @Test("verifyPkcs1 returns false for a mismatched key")
    func verifyPkcs1ReturnsFalseForMismatchedKey() {
        let signingPair = RsaTestKey.generate()
        let otherPair = RsaTestKey.generate()
        let message = Data("machine file payload".utf8)
        let padding = _RSA.Signing.Padding.insecurePKCS1v1_5
        let signature = RsaTestKey.sign(message, with: signingPair.privateKey, padding: padding)

        #expect(!Rsa.verifyPkcs1(publicKeyDER: otherPair.publicKeySPKI, message: message, signature: signature))
    }

    @Test("verifyPkcs1 returns false, not a crash, for a malformed public key")
    func verifyPkcs1ReturnsFalseForMalformedKey() {
        let malformed = Data([0x01, 0x02, 0x03])
        let message = Data("payload".utf8)
        let signature = Data(repeating: 0, count: 256)
        #expect(!Rsa.verifyPkcs1(publicKeyDER: malformed, message: message, signature: signature))
    }
}
