import Crypto
import Foundation
import Testing

@testable import Tamga

@Suite("Ed25519")
struct Ed25519Tests {
    @Test("verify returns true for a valid signature")
    func verifyReturnsTrueForValidSignature() throws {
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("license file payload".utf8)
        let signature = try key.signature(for: message)

        #expect(Ed25519.verify(publicKey: key.publicKey.rawRepresentation, message: message, signature: signature))
    }

    @Test("verify returns false for a tampered message")
    func verifyReturnsFalseForTamperedMessage() throws {
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("license file payload".utf8)
        let signature = try key.signature(for: message)

        let tampered = Data("tampered payload".utf8)
        #expect(!Ed25519.verify(publicKey: key.publicKey.rawRepresentation, message: tampered, signature: signature))
    }

    @Test("verify returns false for a mismatched key")
    func verifyReturnsFalseForMismatchedKey() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let message = Data("license file payload".utf8)
        let signature = try signingKey.signature(for: message)

        let otherPublicKey = otherKey.publicKey.rawRepresentation
        #expect(!Ed25519.verify(publicKey: otherPublicKey, message: message, signature: signature))
    }

    @Test("verify returns false, not a crash, for a malformed public key")
    func verifyReturnsFalseForMalformedKey() {
        let malformedKey = Data([0x01, 0x02, 0x03]) // Ed25519 public keys are always 32 bytes
        let message = Data("license file payload".utf8)
        let signature = Data(repeating: 0, count: 64)

        #expect(!Ed25519.verify(publicKey: malformedKey, message: message, signature: signature))
    }

    @Test("verify returns false, not a crash, for a wrong-length signature")
    func verifyReturnsFalseForWrongLengthSignature() {
        let key = Curve25519.Signing.PrivateKey()
        let tooShort = Data([0x01, 0x02, 0x03]) // Ed25519 signatures are always 64 bytes
        let message = Data("payload".utf8)

        #expect(!Ed25519.verify(publicKey: key.publicKey.rawRepresentation, message: message, signature: tooShort))
    }
}
