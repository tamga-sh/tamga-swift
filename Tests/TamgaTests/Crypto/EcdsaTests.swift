import Crypto
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
        #expect(Ecdsa.verify(publicKey: derKey, message: message, signature: signature.derRepresentation))
    }

    @Test("verify returns false for a tampered message")
    func verifyReturnsFalseForTamperedMessage() throws {
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: Data("original".utf8))

        let derKey = key.publicKey.derRepresentation
        let tampered = Data("tampered".utf8)
        #expect(!Ecdsa.verify(publicKey: derKey, message: tampered, signature: signature.derRepresentation))
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
        #expect(!Ecdsa.verify(publicKey: derKey, message: message, signature: signature.derRepresentation))
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
        let derSignature = try key.signature(for: message).derRepresentation

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

        #expect(!Ecdsa.verify(publicKey: Data(mislabeledSPKI), message: message, signature: derSignature))
    }

    @Test("verify returns false, not a crash, for a malformed public key")
    func verifyReturnsFalseForMalformedKey() {
        let malformed = Data([0x01, 0x02, 0x03])
        let signature = Data(repeating: 0, count: 64)
        #expect(!Ecdsa.verify(publicKey: malformed, message: Data("payload".utf8), signature: signature))
    }

    @Test("verify rejects a raw (r, s) P1363 signature, which is not the wire format")
    func verifyRejectsRawSignatureEncoding() throws {
        // Regression for a real defect: this verifier previously parsed the signature as
        // `rawRepresentation`, so it accepted P1363 and rejected the DER the server actually
        // sends -- meaning every genuine ECDSA machine file failed to verify. A raw signature is
        // exactly 64 bytes; a DER one is ~70-72 and starts with 0x30. Confirmed against a real
        // checked-out fixture in tamga-go/testdata: 71 bytes, first byte 0x30.
        let key = P256.Signing.PrivateKey()
        let message = Data("payload".utf8)
        let signature = try key.signature(for: message)

        #expect(signature.rawRepresentation.count == 64)
        #expect(signature.derRepresentation.first == 0x30)

        #expect(Ecdsa.verify(publicKey: key.publicKey.derRepresentation,
                             message: message,
                             signature: signature.derRepresentation))
        #expect(!Ecdsa.verify(publicKey: key.publicKey.derRepresentation,
                              message: message,
                              signature: signature.rawRepresentation))
    }

    @Test("verify returns false, not a crash, for a wrong-length signature")
    func verifyReturnsFalseForWrongLengthSignature() {
        let key = P256.Signing.PrivateKey()
        let tooShort = Data([0x01, 0x02, 0x03]) // far too short to be a DER SEQUENCE
        let derKey = key.publicKey.derRepresentation

        #expect(!Ecdsa.verify(publicKey: derKey, message: Data("payload".utf8), signature: tooShort))
    }
}
