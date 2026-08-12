import Foundation
import Testing

@testable import Tamga

@Suite("TamgaCheckoutError")
struct ErrorsTests {
    @Test("errorDescription returns the associated message for each message-carrying case")
    func errorDescriptionReturnsAssociatedMessage() {
        #expect(TamgaCheckoutError.offlineFileFormat("bad format").errorDescription == "bad format")
        #expect(TamgaCheckoutError.decryptionFailed("bad key").errorDescription == "bad key")
        #expect(TamgaCheckoutError.unsupportedAlgorithm("bad alg").errorDescription == "bad alg")
        #expect(TamgaCheckoutError.schemeNotSupported("bad scheme").errorDescription == "bad scheme")
        #expect(TamgaCheckoutError.ttlInvalid("bad ttl").errorDescription == "bad ttl")
    }

    @Test("errorDescription returns a fixed message for signatureVerificationFailed")
    func errorDescriptionForSignatureVerificationFailed() {
        let expected = "Signature verification failed -- the file may be forged or corrupted."
        #expect(TamgaCheckoutError.signatureVerificationFailed.errorDescription == expected)
    }

    @Test("localizedDescription surfaces errorDescription via LocalizedError")
    func localizedDescriptionSurfacesErrorDescription() {
        // Confirms the LocalizedError conformance actually wires up to
        // Foundation's Error.localizedDescription bridge, not just that
        // errorDescription itself returns the right string in isolation.
        let error: Error = TamgaCheckoutError.offlineFileFormat("bad format")
        #expect(error.localizedDescription == "bad format")
    }
}
