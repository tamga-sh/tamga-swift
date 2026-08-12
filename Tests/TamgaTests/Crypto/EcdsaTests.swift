import CryptoKit
import Foundation
import Testing

@testable import Tamga

@Suite("Ecdsa")
struct EcdsaTests {
    @Test("verify returns true for a valid P-256 signature")
    func verifyReturnsTrueForValidSignature() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("machine file payload".utf8)
        let signature = try key.signature(for: message)

        let derKey = key.publicKey.derRepresentation
        #expect(Ecdsa.verify(publicKeyDER: derKey, message: message, signature: signature.rawRepresentation))
    }

    @Test("verify returns false for a tampered message")
    func verifyReturnsFalseForTamperedMessage() throws {
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: Data("original".utf8))

        let derKey = key.publicKey.derRepresentation
        let tampered = Data("tampered".utf8)
        #expect(!Ecdsa.verify(publicKeyDER: derKey, message: tampered, signature: signature.rawRepresentation))
    }

    @Test("verify returns false for a genuinely different curve's key and signature (P-384)")
    func verifyReturnsFalseForDifferentCurveKeyAndSignature() throws {
        // A real P-384 key signing its own message, fed into the P-256
        // verifier. CryptoKit's own coordinate-length check already rejects
        // this (P-384's x963 point is 97 bytes vs P-256's 65) -- covered
        // here as a baseline, not the interesting case (see the OID-mismatch
        // test below for that).
        let key = P384.Signing.PrivateKey()
        let message = Data("tamga-swift ecdsa curve-confusion regression test".utf8)
        let signature = try key.signature(for: message)

        let derKey = key.publicKey.derRepresentation
        #expect(!Ecdsa.verify(publicKeyDER: derKey, message: message, signature: signature.rawRepresentation))
    }

    /// Regression test for the curve-confusion bug class this SDK family's
    /// own cross-repo audit found live in tamga-python/go/dotnet: a
    /// generic ECDSA verifier that never checks the key's own curve before
    /// trusting it.
    ///
    /// This is NOT a hypothetical for Swift specifically -- confirmed
    /// directly (empirically) that `CryptoKit`'s
    /// `P256.Signing.PublicKey(derRepresentation:)` does NOT validate the
    /// curve OID in the `AlgorithmIdentifier` it parses, only the resulting
    /// coordinate byte length. A hand-crafted SPKI declaring the secp256k1
    /// curve OID (1.3.132.0.10) but carrying a real P-256 point's raw
    /// coordinates (same 65-byte x963 length, so the length check alone
    /// doesn't catch it) is silently accepted by CryptoKit's own parser.
    /// `Ecdsa.verify`'s explicit OID check (see `Ecdsa.swift` and
    /// `DER.swift`) is what actually closes this -- without it, this exact
    /// test would pass with a `true` result instead of `false`.
    @Test("verify returns false for a mismatched curve OID, even when the coordinate length matches P-256's")
    func verifyReturnsFalseForMismatchedCurveOIDWithMatchingCoordinateLength() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("tamga-swift ecdsa curve-confusion regression test".utf8)
        let rawSignature = try key.signature(for: message).rawRepresentation

        let point = key.publicKey.x963Representation // 65 bytes: 0x04 || X(32) || Y(32)
        #expect(point.count == 65)

        // id-ecPublicKey OID: 1.2.840.10045.2.1
        let idEcPublicKey: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        // secp256k1 OID: 1.3.132.0.10 -- deliberately NOT P-256's 1.2.840.10045.3.1.7
        let secp256k1OID: [UInt8] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]

        var algorithmIdentifier: [UInt8] = [0x30, UInt8(idEcPublicKey.count + secp256k1OID.count)]
        algorithmIdentifier.append(contentsOf: idEcPublicKey)
        algorithmIdentifier.append(contentsOf: secp256k1OID)

        var bitString: [UInt8] = [0x03, UInt8(1 + point.count), 0x00] // 0 unused bits
        bitString.append(contentsOf: point)

        var mislabeledSPKI: [UInt8] = [0x30, UInt8(algorithmIdentifier.count + bitString.count)]
        mislabeledSPKI.append(contentsOf: algorithmIdentifier)
        mislabeledSPKI.append(contentsOf: bitString)

        #expect(!Ecdsa.verify(publicKeyDER: Data(mislabeledSPKI), message: message, signature: rawSignature))
    }

    @Test("verify returns false, not a crash, for a malformed public key")
    func verifyReturnsFalseForMalformedKey() {
        let malformed = Data([0x01, 0x02, 0x03])
        let signature = Data(repeating: 0, count: 64)
        #expect(!Ecdsa.verify(publicKeyDER: malformed, message: Data("payload".utf8), signature: signature))
    }

    @Test("verify returns false, not a crash, for a wrong-length signature")
    func verifyReturnsFalseForWrongLengthSignature() {
        let key = P256.Signing.PrivateKey()
        let tooShort = Data([0x01, 0x02, 0x03]) // P-256 IEEE P1363 signatures are always 64 bytes
        let derKey = key.publicKey.derRepresentation

        #expect(!Ecdsa.verify(publicKeyDER: derKey, message: Data("payload".utf8), signature: tooShort))
    }
}
