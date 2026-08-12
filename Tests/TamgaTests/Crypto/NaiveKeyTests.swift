import Foundation
import Testing

@testable import Tamga

@Suite("NaiveKey")
struct NaiveKeyTests {
    @Test("derive zero-pads a license key shorter than 32 bytes")
    func deriveZeroPadsShortKey() {
        let key = NaiveKey.derive(licenseKey: "short")
        #expect(key.count == NaiveKey.keyLength)
        #expect(Array(key.prefix(5)) == Array("short".utf8))
        #expect(Array(key.suffix(NaiveKey.keyLength - 5)) == Array(repeating: 0, count: NaiveKey.keyLength - 5))
    }

    @Test("derive truncates a license key longer than 32 bytes")
    func deriveTruncatesLongKey() {
        let longKey = String(repeating: "x", count: 40)
        let key = NaiveKey.derive(licenseKey: longKey)
        #expect(key.count == NaiveKey.keyLength)
        #expect(key == Data(longKey.utf8.prefix(NaiveKey.keyLength)))
    }

    @Test("derive passes through a license key exactly 32 bytes long")
    func deriveExactLength() {
        let exact = String(repeating: "a", count: 32)
        let key = NaiveKey.derive(licenseKey: exact)
        #expect(key == Data(exact.utf8))
    }

    @Test("derive is NOT a hash -- it never changes the license key's own bytes")
    func deriveIsNotAHash() {
        // CRITICAL regression: a verifier that runs the key through SHA-256
        // (or any KDF) instead of zero-pad/truncating silently produces the
        // wrong key. Confirm the first N bytes of the output are literally
        // the license key's own UTF-8 bytes, unmodified.
        let licenseKey = "TAMGA-1234-5678-ABCD"
        let key = NaiveKey.derive(licenseKey: licenseKey)
        #expect(Array(key.prefix(licenseKey.utf8.count)) == Array(licenseKey.utf8))
    }
}
