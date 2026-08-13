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

    @Test("the two derivations never collide")
    func theTwoDerivationsNeverCollide() {
        // GOTCHA regression: both are HKDF-SHA256 now, so the only thing
        // keeping them apart is the salt and info. A change that accidentally
        // aligned those would silently let one file type decrypt as the other.
        let machine = Hkdf.deriveMachineFileKey(licenseKey: "TEST-LICENSE-KEY", fingerprint: "license-file")
        let license = Hkdf.deriveLicenseFileKey(licenseKey: "TEST-LICENSE-KEY")
        #expect(machine != license)
    }

    @Test("the license key is not recoverable from the derived key")
    func licenseKeyIsNotRecoverable() {
        // v1 zero-padded the license key, so the derived key literally
        // contained it in cleartext and everything past its length was zero --
        // a stolen `.lic` was a dictionary attack, not a 256-bit one.
        let derived = Hkdf.deriveLicenseFileKey(licenseKey: "SHORT-KEY")
        #expect(derived.count == 32)

        var naive = Array(Data("SHORT-KEY".utf8))
        naive.append(contentsOf: repeatElement(0, count: 32 - naive.count))
        #expect(derived != Data(naive))
        #expect(derived.dropFirst(9).contains { $0 != 0 })
    }

    @Test("license-file derivation is deterministic")
    func licenseDerivationIsDeterministic() {
        #expect(
            Hkdf.deriveLicenseFileKey(licenseKey: "LK-1")
                == Hkdf.deriveLicenseFileKey(licenseKey: "LK-1")
        )
        #expect(
            Hkdf.deriveLicenseFileKey(licenseKey: "LK-1")
                != Hkdf.deriveLicenseFileKey(licenseKey: "LK-2")
        )
    }
}
