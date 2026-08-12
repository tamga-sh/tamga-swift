import CryptoKit
import Foundation
import Testing

@testable import Tamga

@Suite("DER")
struct DERTests {
    @Test("ecNamedCurveOID extracts the correct OID from a real P-256 SPKI")
    func extractsP256OID() {
        let key = P256.Signing.PrivateKey()
        let oid = DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: key.publicKey.derRepresentation)
        #expect(oid == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]) // 1.2.840.10045.3.1.7
    }

    @Test("ecNamedCurveOID extracts the correct OID from a real P-384 SPKI")
    func extractsP384OID() {
        let key = P384.Signing.PrivateKey()
        let oid = DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: key.publicKey.derRepresentation)
        #expect(oid == [0x2B, 0x81, 0x04, 0x00, 0x22]) // 1.3.132.0.34
    }

    @Test("ecNamedCurveOID returns nil for an RSA SPKI (parameters are NULL, not a second OID)")
    func returnsNilForRsaSPKI() {
        let pair = RsaTestKey.generate()
        let oid = DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: pair.publicKeySPKI)
        #expect(oid == nil)
    }

    @Test("ecNamedCurveOID returns nil, not a crash, for malformed input")
    func returnsNilForMalformedInput() {
        #expect(DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: [UInt8]()) == nil)
        #expect(DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: [0x30]) == nil) // truncated: tag with no length
        #expect(DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: [0x30, 0xFF]) == nil) // length says 255 bytes follow, none do
        #expect(DER.ecNamedCurveOID(fromSubjectPublicKeyInfo: Array(repeating: UInt8(0), count: 10)) == nil)
    }

    @Test("readElement rejects an unsupported long-form length size")
    func rejectsOversizedLongFormLength() {
        // 0x30 (SEQUENCE), 0x85 (long-form: 5 length bytes follow -- this
        // reader only supports up to 4).
        let bytes: [UInt8] = [0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01]
        #expect(throws: DER.DERError.self) {
            _ = try DER.readElement(bytes[...])
        }
    }
}
