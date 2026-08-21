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

    /// The SPKI branch's OID check, tested on the only input that actually
    /// isolates it: a real P-256 point wearing the secp256k1 OID
    /// (1.3.132.0.10). Confirmed directly (empirically) that
    /// `P256.Signing.PublicKey(derRepresentation:)` does NOT validate that
    /// OID, so this key parses fine without the guard and this test would
    /// return `true` instead of `false`.
    ///
    /// Do NOT read this as "a foreign-curve signature would otherwise verify".
    /// It would not: a key on a genuinely different curve is rejected on point
    /// validity by both branches (see `verifyRejectsSameLengthWrongCurvePoint`,
    /// which uses a real secp256k1 point), and `Ecdsa.verify` is hardcoded to
    /// P-256 math anyway. What this pins is that a key whose own metadata
    /// contradicts its coordinates is refused rather than quietly trusted --
    /// and that the guard is still there to keep the type from drifting into
    /// the dynamic multi-curve dispatch that made this a live forgery bug in
    /// tamga-python/go/dotnet.
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

    // MARK: - The bare 65-byte X9.63 branch

    /// The server publishes `ecdsa_public_key` as a bare uncompressed point,
    /// not SPKI, so this branch is the one every genuine ECDSA machine file
    /// goes through. The server-issued fixtures cover it end to end; this
    /// covers it directly.
    @Test("verify accepts the bare 65-byte uncompressed point the server actually publishes")
    func verifyAcceptsBareUncompressedPoint() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("machine file payload".utf8)
        let signature = try key.signature(for: message)

        let point = key.publicKey.x963Representation
        #expect(point.count == 65)
        #expect(point.first == 0x04)
        #expect(Ecdsa.verify(publicKey: point, message: message, signature: signature.derRepresentation))
    }

    /// The bare-point branch is the ONLY one with no curve OID to check, so
    /// what stops curve confusion there is `x963Representation`'s own
    /// on-curve validation -- an assumption about the crypto library, which is
    /// exactly the kind that needs a standing test rather than a comment.
    ///
    /// The P-384 case elsewhere in this suite does NOT cover this: a P-384
    /// point is 97 bytes and never takes the 65-byte dispatch. secp256k1 is
    /// the curve that does — its uncompressed points are 65 bytes too, so its
    /// generator reaches this branch and must still be refused.
    @Test("verify rejects a real wrong-curve point of the same 65-byte length (secp256k1 generator)")
    func verifyRejectsSameLengthWrongCurvePoint() throws {
        // secp256k1's generator G. A real point on a real curve, and
        // definitively not on P-256.
        let gx = Data([
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
            0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
        ])
        let gy = Data([
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
            0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
        ])
        var point = Data([0x04])
        point.append(gx)
        point.append(gy)

        // Same length as a P-256 point, so the length check alone cannot catch it.
        #expect(point.count == 65)

        // Asserted at the library boundary, not just through `verify`. A test
        // that only checked `verify(...) == false` would pass even if the key
        // were accepted, because the signature it supplied would not have
        // verified either way -- it would assert nothing about the branch.
        #expect(throws: (any Error).self) {
            _ = try P256.Signing.PublicKey(x963Representation: point)
        }
        #expect(!Ecdsa.verify(publicKey: point, message: Data("payload".utf8),
                              signature: Data(repeating: 0, count: 71)))
    }

    /// The SPKI half of the same claim, and the reason the OID check is
    /// documented as hygiene rather than as the forgery boundary.
    ///
    /// A genuine secp256k1 SPKI — real curve, real point on it, honestly
    /// labelled — is refused by the LIBRARY on point validity, before the SDK's
    /// OID check would ever have mattered. `Ecdsa.verify` rejects it for the
    /// OID first, which is why the library-level assertion is made separately:
    /// without it, this test could not tell "refused because mislabelled" from
    /// "refused because it is not a P-256 point", and the distinction is the
    /// whole content of the claim.
    @Test("a real secp256k1 SPKI is refused by the library on point validity, not merely by the OID check")
    func realSecp256k1SPKIIsRefusedOnPointValidity() throws {
        // openssl ecparam -name secp256k1 -genkey | openssl ec -pubout -outform DER
        let secp256k1SPKI = Data([
            0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
            0x81, 0x04, 0x00, 0x0A, 0x03, 0x42, 0x00, 0x04, 0x8A, 0x4D, 0x70, 0x19, 0xBF, 0xF5, 0xFA, 0x12,
            0x38, 0xDB, 0xEC, 0x8E, 0x3A, 0xB8, 0x47, 0x5F, 0x40, 0xB6, 0x19, 0xEB, 0xBD, 0x20, 0x9D, 0x20,
            0xB2, 0x62, 0x59, 0x27, 0x1F, 0x71, 0x25, 0x70, 0x7B, 0xEE, 0x79, 0x66, 0xE6, 0x77, 0x98, 0x17,
            0x89, 0xBF, 0xCA, 0x56, 0xF9, 0xFF, 0x00, 0xB7, 0x00, 0x8F, 0x88, 0x76, 0x39, 0x72, 0xC2, 0x85,
            0xC8, 0x8A, 0x92, 0x15, 0xF7, 0xB1, 0xA5, 0x24
        ])

        // Long enough that the 65-byte bare-point dispatch cannot claim it.
        #expect(secp256k1SPKI.count > 65)

        #expect(throws: (any Error).self) {
            _ = try P256.Signing.PublicKey(derRepresentation: secp256k1SPKI)
        }
        #expect(!Ecdsa.verify(publicKey: secp256k1SPKI, message: Data("payload".utf8),
                              signature: Data(repeating: 0, count: 71)))
    }

    @Test("verify rejects a bare point that is not on the P-256 curve")
    func verifyRejectsOffCurveBarePoint() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("machine file payload".utf8)
        let signature = try key.signature(for: message)

        var offCurve = Data(key.publicKey.x963Representation)
        offCurve[offCurve.count - 1] ^= 0x01 // one bit of Y: no longer satisfies the curve equation
        #expect(offCurve.count == 65)

        // Same reasoning as above: pin the rejection where it actually happens.
        #expect(throws: (any Error).self) {
            _ = try P256.Signing.PublicKey(x963Representation: offCurve)
        }
        #expect(!Ecdsa.verify(publicKey: offCurve, message: message, signature: signature.derRepresentation))
    }

    // MARK: - Malformed input

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
