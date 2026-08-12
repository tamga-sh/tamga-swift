import Foundation
import Testing

@testable import Tamga

@Suite("Hkdf")
struct HkdfTests {
    @Test("deriveMachineFileKey produces a 32-byte key")
    func deriveProducesCorrectLength() {
        let key = Hkdf.deriveMachineFileKey(licenseKey: "TEST-LICENSE-KEY", fingerprint: "machine-fingerprint-abc123")
        #expect(key.count == Hkdf.keyLength)
    }

    @Test("deriveMachineFileKey is deterministic for the same inputs")
    func deriveIsDeterministic() {
        let key1 = Hkdf.deriveMachineFileKey(licenseKey: "TEST-LICENSE-KEY", fingerprint: "fp-1")
        let key2 = Hkdf.deriveMachineFileKey(licenseKey: "TEST-LICENSE-KEY", fingerprint: "fp-1")
        #expect(key1 == key2)
    }

    @Test("deriveMachineFileKey differs when the fingerprint differs")
    func deriveDiffersByFingerprint() {
        let key1 = Hkdf.deriveMachineFileKey(licenseKey: "TEST-LICENSE-KEY", fingerprint: "fp-1")
        let key2 = Hkdf.deriveMachineFileKey(licenseKey: "TEST-LICENSE-KEY", fingerprint: "fp-2")
        #expect(key1 != key2)
    }

    @Test("deriveMachineFileKey differs when the license key differs")
    func deriveDiffersByLicenseKey() {
        let key1 = Hkdf.deriveMachineFileKey(licenseKey: "LICENSE-A", fingerprint: "fp-1")
        let key2 = Hkdf.deriveMachineFileKey(licenseKey: "LICENSE-B", fingerprint: "fp-1")
        #expect(key1 != key2)
    }

    @Test("deriveMachineFileKey differs from NaiveKey.derive for the same license key")
    func deriveDiffersFromNaiveKey() {
        // GOTCHA regression: the two key-derivation paths (real HKDF here vs.
        // NaiveKey's zero-pad/truncate) must never be conflated -- confirm
        // they actually produce different output for the same license key,
        // not just that the code compiles as two separate call sites.
        let hkdfKey = Hkdf.deriveMachineFileKey(licenseKey: "TEST-LICENSE-KEY", fingerprint: "fp-1")
        let naiveKey = NaiveKey.derive(licenseKey: "TEST-LICENSE-KEY")
        #expect(hkdfKey != naiveKey)
    }
}
