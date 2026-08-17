import Foundation

/// The inner `{enc, sig, alg}` JSON structure carried inside a `.machine`
/// file's PEM envelope -- same shape as `LicenseFileCertificate`.
struct MachineFileCertificate: Decodable {
    /// The payload: base64-encoded AES-256-GCM ciphertext (encrypted files)
    /// or plain base64-encoded JSON (unencrypted files).
    let enc: String
    /// The signature over `enc`'s base64 string bytes, base64-encoded.
    let sig: String
    /// The algorithm identifier reported by the server (e.g. contains
    /// `"aes-256-gcm"` and/or a signature-scheme suffix like `"rsa-sha256"`).
    /// NEVER used to select the verifier -- see `MachineFile`'s type-level
    /// remarks.
    let alg: String
}

/// Parses, verifies, and decrypts an offline `.machine` file:
/// ```
/// -----BEGIN MACHINE FILE-----
/// <base64 of JSON: { "enc": "<base64>", "sig": "<base64 sig>", "alg": "..." }>
/// -----END MACHINE FILE-----
/// ```
/// Same inner `{enc, sig, alg}` JSON shape as `LicenseFile`.
///
/// GOTCHA: signing scheme is taken from the LICENSE's `scheme` field
/// (`LicenseScheme`), NOT hardcoded Ed25519 like license checkout. This
/// type's verify dispatch selects Ed25519 / RSA-PKCS1 / RSA-PSS / ECDSA-P256
/// based on a caller-supplied `LicenseScheme` parameter -- NEVER by parsing
/// this file's own `alg` string, since `RSA_2048_PKCS1_SIGN` and
/// `RSA_2048_JWT_RS256` both serialize to the same `"rsa-sha256"` `alg`
/// suffix server-side (an algorithm-confusion risk if dispatch were keyed on
/// the self-declared string instead of the caller's own trusted scheme
/// value). An unset license scheme (`.none`) defaults to Ed25519, matching
/// server behavior.
///
/// `RSA_2048_JWT_RS256` is explicitly rejected server-side for machine files
/// (`422 SCHEME_NOT_SUPPORTED`) -- this type's verifier does NOT implement
/// or attempt JWT/RS256 verification for machine files; it throws
/// `TamgaCheckoutError.schemeNotSupported` immediately rather than silently
/// no-op-ing.
///
/// Encryption key derivation is HKDF-SHA256 (`Hkdf.deriveMachineFileKey`):
/// `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`,
/// `info = <fingerprint>`. License files use the same primitive with a
/// different salt and info (`Hkdf.deriveLicenseFileKey`) -- same KDF, never
/// the same key. Decryption here requires BOTH the license key AND the target
/// machine's fingerprint, which is what binds a machine file to one machine.
///
/// Unlike a license file, a machine file carries no signed `meta` claims and
/// is not subject to the `+v2` `alg` check -- its expiry is not enforced
/// client-side here.
///
/// GOTCHA: `ttl` is server-validated `> 0 && <= 31536000` (365
/// days) -- the SDK's checkout call validates this client-side too, to fail
/// fast, in addition to handling the server's `422 TTL_INVALID`.
///
/// RSA and ECDSA public keys are expected in X.509 `SubjectPublicKeyInfo`
/// DER encoding; Ed25519 public keys are raw 32-byte keys, matching
/// `LicenseFile`.
public struct MachineFile: Sendable {
    private static let beginMarker = "-----BEGIN MACHINE FILE-----"
    private static let endMarker = "-----END MACHINE FILE-----"

    /// The maximum `ttl` the server accepts for machine checkout: 365 days
    /// in seconds.
    public static let maxTtlSeconds = 31_536_000

    /// The parsed, unverified `{enc, sig, alg}` certificate.
    let certificate: MachineFileCertificate

    private init(certificate: MachineFileCertificate) {
        self.certificate = certificate
    }

    /// Parses a PEM-wrapped `.machine` file. Does NOT verify the signature.
    public static func parse(_ pem: String) throws -> MachineFile {
        let inner = try PemEnvelope.strip(pem, beginMarker: beginMarker, endMarker: endMarker)
        guard let jsonBytes = Data(base64Encoded: inner) else {
            throw TamgaCheckoutError.offlineFileFormat("Machine file body is not valid base64.")
        }

        let certificate: MachineFileCertificate
        do {
            certificate = try TamgaJSONCoding.decoder.decode(MachineFileCertificate.self, from: jsonBytes)
        } catch {
            throw TamgaCheckoutError.offlineFileFormat("Machine file certificate JSON is malformed: \(error)")
        }

        return MachineFile(certificate: certificate)
    }

    /// Client-side validation mirroring the server's `422 TTL_INVALID` check
    /// -- fails fast before a checkout request is even sent.
    public static func validateTtl(_ ttl: Int) throws {
        guard ttl > 0, ttl <= maxTtlSeconds else {
            throw TamgaCheckoutError.ttlInvalid("ttl must be > 0 and <= \(maxTtlSeconds) (365 days); got \(ttl).")
        }
    }

    /// Verifies the signature against the account's public key, dispatching
    /// by the caller-supplied `scheme` -- NEVER by parsing this file's own
    /// `alg` string. See type-level remarks for the algorithm-confusion
    /// rationale.
    ///
    /// - Throws: `TamgaCheckoutError.schemeNotSupported` if `scheme` is
    ///   `.rsa2048JwtRs256` -- never implemented for machine files.
    public func verify(scheme: LicenseScheme, publicKey: Data) throws -> Bool {
        guard let signature = Data(base64Encoded: certificate.sig) else {
            return false
        }
        let message = Data(certificate.enc.utf8)

        switch scheme {
        case .rsa2048JwtRs256:
            throw TamgaCheckoutError.schemeNotSupported(
                "RSA_2048_JWT_RS256 is rejected server-side for machine files (422 SCHEME_NOT_SUPPORTED) " +
                "and is not implemented client-side either -- this SDK never attempts JWT/RS256 verification."
            )
        case .none, .ed25519Sign:
            return Ed25519.verify(publicKey: publicKey, message: message, signature: signature)
        case .rsa2048Pkcs1Sign:
            return Rsa.verifyPkcs1(publicKeyDER: publicKey, message: message, signature: signature)
        case .rsa2048Pkcs1PssSign:
            return Rsa.verifyPss(publicKeyDER: publicKey, message: message, signature: signature)
        case .ecdsaP256Sign:
            return Ecdsa.verify(publicKeyDER: publicKey, message: message, signature: signature)
        }
    }

    /// Full verify pipeline: verifies the signature (fails closed), then
    /// decrypts (if `alg` indicates AES-256-GCM, using the HKDF-derived key
    /// -- see `Hkdf`) or plain-decodes the `enc` payload, and parses the
    /// embedded `{"data": <MachineResource>}` JSON.
    ///
    /// - Parameter scheme: the license's signing scheme -- drives verifier
    ///   dispatch, see type-level remarks.
    /// - Parameter licenseKey: HKDF input keying material for an encrypted
    ///   file.
    /// - Parameter fingerprint: the target machine's fingerprint -- HKDF
    ///   `info` for an encrypted file. Decryption fails closed (AES-GCM auth
    ///   failure) if this doesn't match the machine the file was issued for.
    public func verifyAndDecrypt(
        scheme: LicenseScheme, publicKey: Data, licenseKey: String, fingerprint: String
    ) throws -> Machine {
        guard try verify(scheme: scheme, publicKey: publicKey) else {
            throw TamgaCheckoutError.signatureVerificationFailed
        }

        guard let payloadBytes = Data(base64Encoded: certificate.enc) else {
            throw TamgaCheckoutError.offlineFileFormat("Machine file 'enc' is not valid base64.")
        }

        // Substring matching, NOT exact equality, is intentional and
        // required here -- unlike LicenseFile's fixed 2-literal `alg` space,
        // MachineFile's `alg` is a compound encryption-prefix +
        // signature-suffix string across 5 possible schemes (e.g.
        // "aes-256-gcm+ed25519", "rsa-sha256", "ecdsa-sha256"), so there is
        // no single fixed literal set to match exactly. Matches
        // tamga-dotnet's reference `MachineFile.Contains(...)` pattern
        // exactly (confirmed by direct comparison against
        // Tamga.Sdk/Checkout/MachineFile.cs). `alg` is never used for
        // signature-scheme dispatch (see `verify(scheme:publicKey:)` above)
        // -- only for this encrypted-vs-plain payload gating.
        let jsonBytes: Data
        if certificate.alg.contains("aes-256-gcm") {
            jsonBytes = try Self.decryptPayload(payloadBytes, licenseKey: licenseKey, fingerprint: fingerprint)
        } else if certificate.alg.contains("base64") {
            jsonBytes = payloadBytes
        } else {
            throw TamgaCheckoutError.unsupportedAlgorithm("Unsupported machine file algorithm: '\(certificate.alg)'.")
        }

        let payload: JSONAPIPayload<MachineAttributes>
        do {
            payload = try TamgaJSONCoding.decoder.decode(JSONAPIPayload<MachineAttributes>.self, from: jsonBytes)
        } catch {
            throw TamgaCheckoutError.offlineFileFormat("Machine file payload JSON is malformed: \(error)")
        }

        return Machine.fromResource(payload.data)
    }

    private static func decryptPayload(_ payloadBytes: Data, licenseKey: String, fingerprint: String) throws -> Data {
        let key = Hkdf.deriveMachineFileKey(licenseKey: licenseKey, fingerprint: fingerprint)
        return try EncryptedPayloadDecryptor.decrypt(payloadBytes, key: key, context: "Encrypted machine file")
    }
}
