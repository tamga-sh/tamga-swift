import Foundation
import Testing

@testable import Tamga

@Suite("MachineProof")
struct ProofTests {
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
        #expect(payload == #"{"account":{"id":"acc-1"},"dataset":{"seat_count":5},"machine":{"fingerprint":"fp-1","id":"mach-1"}}"#)
    }

    @Test("verify returns true for a valid signature over the canonical payload")
    func verifyReturnsTrueForValidSignature() {
        let pair = RsaTestKey.generate()
        let payload = MachineProof.buildSignedPayload(accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object([:]))
        let signatureBytes = RsaTestKey.sign(Data(payload.utf8), with: pair.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
        let proof = try! MachineProof.parse("v1x0." + signatureBytes.base64EncodedString())

        #expect(proof.verify(publicKeyDER: pair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object([:])))
    }

    @Test("verify returns false when the dataset was altered after signing")
    func verifyReturnsFalseForAlteredDataset() {
        let pair = RsaTestKey.generate()
        let signedPayload = MachineProof.buildSignedPayload(accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object(["seats": .int(5)]))
        let signatureBytes = RsaTestKey.sign(Data(signedPayload.utf8), with: pair.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
        let proof = try! MachineProof.parse("v1x0." + signatureBytes.base64EncodedString())

        // Verify against a DIFFERENT dataset than what was actually signed.
        #expect(!proof.verify(publicKeyDER: pair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object(["seats": .int(99)])))
    }

    @Test("verify returns false for a mismatched key")
    func verifyReturnsFalseForMismatchedKey() {
        let signingPair = RsaTestKey.generate()
        let otherPair = RsaTestKey.generate()
        let payload = MachineProof.buildSignedPayload(accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object([:]))
        let signatureBytes = RsaTestKey.sign(Data(payload.utf8), with: signingPair.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
        let proof = try! MachineProof.parse("v1x0." + signatureBytes.base64EncodedString())

        #expect(!proof.verify(publicKeyDER: otherPair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object([:])))
    }

    @Test("verify returns false, not a crash, for a malformed base64 signature")
    func verifyReturnsFalseForMalformedSignature() {
        let pair = RsaTestKey.generate()
        let proof = try! MachineProof.parse("v1x0.not-valid-base64!!!")

        #expect(!proof.verify(publicKeyDER: pair.publicKeySPKI, accountId: "acc-1", machineId: "mach-1", fingerprint: "fp-1", dataset: .object([:])))
    }
}
