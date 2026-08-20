import CryptoExtras
import Foundation
import Testing

@testable import Tamga

@Suite("MachineProof")
struct ProofTests {
    /// Signs `payload` with `privateKey` and wraps it in a `"v1x0."`-prefixed
    /// `MachineProof`, matching what `parse` expects from a real
    /// `meta.proof` string.
    private static func signedProof(payload: String, privateKey: _RSA.Signing.PrivateKey) throws -> MachineProof {
        let padding = _RSA.Signing.Padding.insecurePKCS1v1_5
        let signature = RsaTestKey.sign(Data(payload.utf8), with: privateKey, padding: padding)
        return try MachineProof.parse("v1x0." + signature.base64EncodedString())
    }

    @Test("parse splits the v1x0. prefix from the signature")
    func parseSplitsVersionPrefix() throws {
        let proof = try MachineProof.parse("v1x0.dGVzdC1zaWduYXR1cmU=")
        #expect(proof.rawSignatureBase64 == "dGVzdC1zaWduYXR1cmU=")
    }

    @Test("parse throws unsupportedAlgorithm for a missing version prefix")
    func parseThrowsForMissingPrefix() {
        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineProof.parse("dGVzdA==")
        }
    }

    @Test("parse throws offlineFileFormat for an empty signature after the prefix")
    func parseThrowsForEmptySignature() {
        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineProof.parse("v1x0.")
        }
    }

    @Test("buildSignedPayload produces the documented canonical field order")
    func buildSignedPayloadProducesCanonicalOrder() {
        let payload = MachineProof.buildSignedPayload(
            accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1",
            dataset: .object(["seat_count": .int(5)])
        )
        let expected = #"""
        {"account":{"id":"acc-1"},"dataset":{"seat_count":5},"machine":{"fingerprint":"fp-1","id":"mach-1"}}
        """#
        #expect(payload == expected)
    }

    @Test("verify returns true for a valid signature over the canonical payload")
    func verifyReturnsTrueForValidSignature() throws {
        let pair = RsaTestKey.generate()
        let payload = MachineProof.buildSignedPayload(
            accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object([:])
        )
        let proof = try Self.signedProof(payload: payload, privateKey: pair.privateKey)

        let verified = proof.verify(
            publicKeyDER: pair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1",
            fingerprint: "fp-1", dataset: .object([:])
        )
        #expect(verified)
    }

    @Test("verify returns false when the dataset was altered after signing")
    func verifyReturnsFalseForAlteredDataset() throws {
        let pair = RsaTestKey.generate()
        let signedPayload = MachineProof.buildSignedPayload(
            accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object(["seats": .int(5)])
        )
        let proof = try Self.signedProof(payload: signedPayload, privateKey: pair.privateKey)

        // Verify against a DIFFERENT dataset than what was actually signed.
        let verified = proof.verify(
            publicKeyDER: pair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1",
            fingerprint: "fp-1", dataset: .object(["seats": .int(99)])
        )
        #expect(!verified)
    }

    @Test("verify returns false for a mismatched key")
    func verifyReturnsFalseForMismatchedKey() throws {
        let signingPair = RsaTestKey.generate()
        let otherPair = RsaTestKey.generate()
        let payload = MachineProof.buildSignedPayload(
            accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object([:])
        )
        let proof = try Self.signedProof(payload: payload, privateKey: signingPair.privateKey)

        let verified = proof.verify(
            publicKeyDER: otherPair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1",
            fingerprint: "fp-1", dataset: .object([:])
        )
        #expect(!verified)
    }

    @Test("verify returns false, not a crash, for a malformed base64 signature")
    func verifyReturnsFalseForMalformedSignature() throws {
        let pair = RsaTestKey.generate()
        let proof = try MachineProof.parse("v1x0.not-valid-base64!!!")

        let verified = proof.verify(
            publicKeyDER: pair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1",
            fingerprint: "fp-1", dataset: .object([:])
        )
        #expect(!verified)
    }
}
