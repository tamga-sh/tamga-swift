import Foundation

/// The parsed form of a machine file's `alg` string.
///
/// The server builds it in exactly one place -- `machine_file_alg_str`
/// (`src/shared/crypto/machine_file.rs`) -- as:
///
/// ```
/// "<encoding>+<signing suffix>+v2"
/// ```
///
/// | part | values |
/// |---|---|
/// | encoding | `base64` (plain) · `aes-256-gcm` (encrypted) |
/// | signing suffix | `ed25519` · `ecdsa-p256` · `rsa-sha256` · `rsa-pss-sha256` |
///
/// so a default plain file is `base64+ed25519+v2` and an encrypted ECDSA one is
/// `aes-256-gcm+ecdsa-p256+v2`.
///
/// CRITICAL -- why this is a real parse and not a substring test. This type
/// replaces a `certificate.alg.contains("aes-256-gcm")` / `.contains("base64")`
/// pair that accepted the genuine strings by luck rather than by understanding
/// them. `contains` would equally accept `base64+ed25519+v3`, or
/// `xbase64+ed25519+v2junk`, or an `alg` that names one encoding inside a
/// longer token that means something else. `alg` is NOT covered by the
/// signature -- the server signs `enc`'s string bytes and nothing else -- so
/// every byte of it is attacker-controlled on a file that otherwise verifies.
/// A permissive reading of an attacker-controlled field guarding a decrypt
/// branch is exactly the shape worth being strict about.
///
/// The two delimiters are found from opposite ends on purpose: encoding
/// (`aes-256-gcm`) and two of the four signing suffixes (`rsa-pss-sha256`,
/// `ecdsa-p256`) contain hyphens, and `rsa-pss-sha256` contains `rsa-sha256`
/// as a substring. Splitting at the FIRST `+` and the LAST `+` is the only
/// reading that survives all four suffixes; `split(separator:)` with an index
/// lookup, or a `split_once` whose remainder is compared whole, is not.
struct MachineFileAlgorithm: Equatable, Sendable {
    /// How `enc` is encoded, which selects the payload branch after the
    /// signature has been checked.
    enum Encoding: String, Equatable, Sendable {
        /// `enc` is a single base64 blob of the payload JSON.
        case base64
        /// `enc` is `"<nonce_b64>.<cipher_b64>"` -- two independently
        /// base64-encoded halves. See `EncryptedPayloadDecryptor`.
        case aes256Gcm = "aes-256-gcm"
    }

    /// The mandatory format marker. A file without it is rejected: v1 carried
    /// no `meta.exp` inside the signed payload and derived its AES key by
    /// zero-padding the license key instead of through HKDF, so accepting one
    /// silently reinstates both weaknesses -- an offline file whose expiry is
    /// never enforced, encrypted under a key with the license key's own
    /// entropy. Downgrading a v2 file to v1 costs an attacker one edit to a
    /// field the signature does not cover, which is precisely why the check is
    /// here and not left to the server.
    static let versionMarker = "v2"

    let encoding: Encoding
    /// The signing-algorithm suffix as the file declares it. A cross-check
    /// only -- never the input to verifier dispatch. See `signingSuffix(for:)`.
    let signingSuffix: String

    /// Parses `alg`, rejecting anything that is not a well-formed v2 machine
    /// file algorithm string.
    ///
    /// - Throws: `TamgaCheckoutError.unsupportedAlgorithm` for a missing or
    ///   non-`v2` version marker, an unrecognised encoding prefix, an empty
    ///   signing suffix, or a string with fewer than three `+`-separated
    ///   segments.
    static func parse(_ alg: String) throws -> MachineFileAlgorithm {
        guard let firstPlus = alg.firstIndex(of: "+"),
              let lastPlus = alg.lastIndex(of: "+"),
              firstPlus < lastPlus
        else {
            throw TamgaCheckoutError.unsupportedAlgorithm(
                "Unsupported machine file algorithm: '\(alg)'. Expected '<encoding>+<signing>+v2'."
            )
        }

        let version = String(alg[alg.index(after: lastPlus)...])
        // Checked before anything else that could look like a reason to
        // proceed: a v1 file is refused for what it lacks, not for how its
        // other segments happen to be spelled.
        guard version == versionMarker else {
            throw TamgaCheckoutError.unsupportedAlgorithm(
                "Unsupported machine file algorithm: '\(alg)'. Missing the mandatory '+\(versionMarker)' marker " +
                "-- a pre-v2 file carries no signed 'meta.exp' and derives its AES key without HKDF, " +
                "so it is rejected rather than verified."
            )
        }

        let encodingPart = String(alg[alg.startIndex..<firstPlus])
        guard let encoding = Encoding(rawValue: encodingPart) else {
            throw TamgaCheckoutError.unsupportedAlgorithm(
                "Unsupported machine file algorithm: '\(alg)'. Unrecognised encoding prefix '\(encodingPart)' " +
                "-- expected '\(Encoding.base64.rawValue)' or '\(Encoding.aes256Gcm.rawValue)'."
            )
        }

        let signingSuffix = String(alg[alg.index(after: firstPlus)..<lastPlus])
        guard !signingSuffix.isEmpty else {
            throw TamgaCheckoutError.unsupportedAlgorithm(
                "Unsupported machine file algorithm: '\(alg)'. Empty signing-algorithm suffix."
            )
        }

        return MachineFileAlgorithm(encoding: encoding, signingSuffix: signingSuffix)
    }

    /// The suffix the server emits for `scheme`, mirroring
    /// `scheme_to_alg_suffix` server-side.
    ///
    /// `nil` for `.rsa2048JwtRs256`, which has no verifiable machine-file
    /// form: the server refuses it at checkout with `422
    /// SCHEME_NOT_SUPPORTED`, and this SDK refuses it before any parsing.
    ///
    /// NOTE the mapping is deliberately not invertible. `RSA_2048_PKCS1_SIGN`
    /// and `RSA_2048_JWT_RS256` both serialize to `rsa-sha256` server-side, so
    /// the suffix cannot name the scheme -- which is the whole reason the
    /// scheme must arrive from the caller's own trusted license record and the
    /// file's `alg` gets used only to check the two agree.
    static func signingSuffix(for scheme: LicenseScheme) -> String? {
        switch scheme {
        // `.none` means the license has no scheme configured, and the server
        // signs those with Ed25519 -- the same default `verify` dispatches on.
        case .none, .ed25519Sign:
            return "ed25519"
        case .ecdsaP256Sign:
            return "ecdsa-p256"
        case .rsa2048Pkcs1Sign:
            return "rsa-sha256"
        case .rsa2048Pkcs1PssSign:
            return "rsa-pss-sha256"
        case .rsa2048JwtRs256:
            return nil
        }
    }
}
