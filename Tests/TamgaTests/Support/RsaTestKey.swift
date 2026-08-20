import Foundation
import _CryptoExtras

/// Test-only RSA-2048 keypair generation and signing, on the same
/// `_CryptoExtras` backend production code uses.
///
/// This used to go through the Security framework's `SecKey` API, which made
/// the test target Apple-only even once the library itself was portable, and
/// forced a hand-rolled DER wrapper because
/// `SecKeyCopyExternalRepresentation` returns a bare PKCS#1 `RSAPublicKey`
/// rather than the X.509 `SubjectPublicKeyInfo` the server sends.
///
/// `_RSA.Signing.PublicKey.derRepresentation` is already SPKI -- confirmed
/// empirically, not assumed: it is 294 bytes for a 2048-bit key where the
/// bare PKCS#1 form (`pkcs1DERRepresentation`) is 270. So the SPKI-parsing
/// path production code actually exercises is still the one under test, with
/// no hand-rolled ASN.1 left in this file.
enum RsaTestKey {
    struct Pair {
        let privateKey: _RSA.Signing.PrivateKey
        /// X.509 SubjectPublicKeyInfo DER encoding of the public key.
        let publicKeySPKI: Data
    }

    static func generate() -> Pair {
        guard let privateKey = try? _RSA.Signing.PrivateKey(keySize: .bits2048) else {
            fatalError("RSA test key generation failed")
        }
        return Pair(privateKey: privateKey, publicKeySPKI: privateKey.publicKey.derRepresentation)
    }

    /// Signs `message` for building test fixtures. `fatalError`s on failure --
    /// this is test-only helper code, not a production path with a
    /// fail-closed contract to uphold.
    static func sign(_ message: Data, with privateKey: _RSA.Signing.PrivateKey,
                     padding: _RSA.Signing.Padding) -> Data {
        guard let signature = try? privateKey.signature(for: message, padding: padding) else {
            fatalError("RSA test signing failed")
        }
        return signature.rawRepresentation
    }
}
