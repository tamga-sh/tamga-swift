import Foundation
import Security

/// Test-only RSA-2048 keypair generation, producing a public key in the
/// same X.509 `SubjectPublicKeyInfo` DER encoding the real server sends
/// (`Rsa.swift`'s production import path) -- not the bare PKCS#1
/// `RSAPublicKey` structure `SecKeyCopyExternalRepresentation` returns on
/// its own. Confirmed directly: `SecKeyCreateWithData` happens to accept
/// both PKCS#1 and SPKI for RSA, but testing only against the bare PKCS#1
/// shape it returns natively would silently skip exercising the SPKI-parsing
/// path production code actually uses.
enum RsaTestKey {
    struct Pair {
        let privateKey: SecKey
        /// X.509 SubjectPublicKeyInfo DER encoding of the public key.
        let publicKeySPKI: Data
    }

    static func generate() -> Pair {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            fatalError("RSA test key generation failed: \(describe(error))")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
        else {
            fatalError("RSA public key export failed: \(describe(error))")
        }
        return Pair(privateKey: privateKey, publicKeySPKI: wrapInSubjectPublicKeyInfo(pkcs1RSAPublicKey: pkcs1))
    }

    /// Signs `message` with the given RSA algorithm, for building test
    /// fixtures. `fatalError`s on failure -- this is test-only helper code,
    /// not a production code path with a fail-closed contract to uphold.
    static func sign(_ message: Data, with privateKey: SecKey, algorithm: SecKeyAlgorithm) -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, message as CFData, &error) as Data? else {
            fatalError("RSA test signing failed: \(describe(error))")
        }
        return signature
    }

    /// Renders a `SecKey` API's `Unmanaged<CFError>?` out-parameter for a
    /// `fatalError` message without a force-unwrap.
    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error else { return "unknown error" }
        return String(describing: error.takeRetainedValue())
    }

    /// Wraps a bare PKCS#1 `RSAPublicKey` DER structure (what
    /// `SecKeyCopyExternalRepresentation` returns for an RSA key) in an
    /// X.509 `SubjectPublicKeyInfo`:
    /// `SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING pkcs1 }`.
    private static func wrapInSubjectPublicKeyInfo(pkcs1RSAPublicKey pkcs1: Data) -> Data {
        // rsaEncryption OID: 1.2.840.113549.1.1.1
        let rsaEncryptionOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let nullParameters: [UInt8] = [0x05, 0x00]

        var algorithmIdentifier: [UInt8] = [0x30, UInt8(rsaEncryptionOID.count + nullParameters.count)]
        algorithmIdentifier.append(contentsOf: rsaEncryptionOID)
        algorithmIdentifier.append(contentsOf: nullParameters)

        var bitString = derLengthPrefixed(tag: 0x03, contentLength: 1 + pkcs1.count)
        bitString.append(0x00) // 0 unused bits
        bitString.append(contentsOf: pkcs1)

        var spki = derLengthPrefixed(tag: 0x30, contentLength: algorithmIdentifier.count + bitString.count)
        spki.append(contentsOf: algorithmIdentifier)
        spki.append(contentsOf: bitString)
        return Data(spki)
    }

    /// Builds a DER tag+length header for `contentLength` bytes of content,
    /// using short-form length for <128 bytes and 1- or 2-byte long-form
    /// length otherwise -- sufficient for the small structures this helper
    /// builds (a 2048-bit RSA key's SPKI is a few hundred bytes).
    private static func derLengthPrefixed(tag: UInt8, contentLength: Int) -> [UInt8] {
        var header: [UInt8] = [tag]
        if contentLength < 128 {
            header.append(UInt8(contentLength))
        } else if contentLength < 256 {
            header.append(0x81)
            header.append(UInt8(contentLength))
        } else {
            header.append(0x82)
            header.append(UInt8((contentLength >> 8) & 0xFF))
            header.append(UInt8(contentLength & 0xFF))
        }
        return header
    }
}
