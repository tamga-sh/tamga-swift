import CryptoKit
import Foundation

/// Ed25519 signature verification, backed by CryptoKit's `Curve25519.Signing`
/// (native since iOS 13 / macOS 10.15 -- well below this package's iOS
/// 16 / macOS 13 floor, no third-party dependency needed).
///
/// Used by `Checkout.LicenseFile` (Ed25519 is the ONLY signature scheme for
/// license checkout files) and `Checkout.MachineFile` (the Ed25519 branch of
/// its scheme-dispatched verifier).
enum Ed25519 {
    /// Verifies `signature` over `message` using a raw 32-byte Ed25519
    /// public key. Returns `false` (never throws) for a malformed key or a
    /// failed verification -- callers must fail closed on a `false` result.
    static func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return false
        }
        return key.isValidSignature(signature, for: message)
    }
}
