import Foundation
import Security

/// RSA-2048 signature verification (PKCS#1 v1.5 and PSS, both SHA-256) via
/// the Security framework's `SecKey` API. CryptoKit deliberately does not
/// expose RSA (it only covers modern curve-based/AEAD primitives), so this
/// is the one crypto primitive in this SDK that isn't CryptoKit -- confirmed
/// against Apple's own documentation before writing this, not assumed.
///
/// Used by `Checkout.MachineFile` (PKCS1 and PSS branches of the
/// scheme-dispatched machine-file verifier) and `MachineProof` (offline
/// proof verification is ALWAYS RSA-2048 PKCS#1 v1.5 / SHA-256, regardless
/// of the license's scheme).
enum Rsa {
    /// Imports an RSA public key from X.509 `SubjectPublicKeyInfo` DER
    /// bytes. Confirmed directly: unlike EC keys, `SecKeyCreateWithData`
    /// unwraps a full X.509 SPKI for `kSecAttrKeyTypeRSA` on its own -- no
    /// manual ASN.1 stripping down to the bare PKCS#1 `RSAPublicKey`
    /// structure is needed.
    private static func importPublicKey(fromSubjectPublicKeyInfo der: Data) -> SecKey? {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil)
    }

    /// Verifies an RSA-PKCS#1 v1.5/SHA-256 signature.
    static func verifyPkcs1(publicKeyDER: Data, message: Data, signature: Data) -> Bool {
        verify(publicKeyDER: publicKeyDER, message: message, signature: signature, algorithm: .rsaSignatureMessagePKCS1v15SHA256)
    }

    /// Verifies an RSA-PSS/SHA-256 signature.
    static func verifyPss(publicKeyDER: Data, message: Data, signature: Data) -> Bool {
        verify(publicKeyDER: publicKeyDER, message: message, signature: signature, algorithm: .rsaSignatureMessagePSSSHA256)
    }

    private static func verify(publicKeyDER: Data, message: Data, signature: Data, algorithm: SecKeyAlgorithm) -> Bool {
        guard let key = importPublicKey(fromSubjectPublicKeyInfo: publicKeyDER) else {
            return false
        }
        // SecKeyVerifySignature reports failure via the CFError out-parameter,
        // not a thrown Swift error -- both a malformed signature and a
        // genuine verification failure land here as `false`, which is the
        // fail-closed behavior every caller of this type relies on.
        return SecKeyVerifySignature(key, algorithm, message as CFData, signature as CFData, nil)
    }
}
