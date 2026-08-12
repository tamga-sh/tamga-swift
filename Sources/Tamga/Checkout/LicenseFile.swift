import Foundation

/// The inner `{enc, sig, alg}` JSON structure carried inside a `.lic` file's
/// PEM envelope.
struct LicenseFileCertificate: Decodable {
    /// Base64-encoded license payload -- either AES-256-GCM ciphertext
    /// (encrypted license) or plain JSON (unencrypted), depending on `alg`.
    let enc: String
    /// Base64-encoded Ed25519 signature, computed over the ASCII/UTF-8 bytes
    /// of `enc`'s base64 string itself, not the decoded payload bytes.
    let sig: String
    /// Algorithm identifier -- exactly `"base64+ed25519"` (plain) or
    /// `"aes-256-gcm+ed25519"` (encrypted).
    let alg: String
}

/// Parses, verifies, and decrypts an offline `.lic` license file:
/// ```
/// -----BEGIN LICENSE FILE-----
/// <base64 of JSON: { "enc": "<base64>", "sig": "<base64 ed25519 sig>", "alg": "..." }>
/// -----END LICENSE FILE-----
/// ```
///
/// `alg` is exactly `"base64+ed25519"` (plain) or `"aes-256-gcm+ed25519"`
/// (encrypted) -- Ed25519 ONLY for the checkout signature, independent of
/// the license's own `scheme` (contrast with `MachineFile`, which dispatches
/// by scheme).
///
/// CRITICAL -- the single most consequential correctness trap in this SDK:
/// the Ed25519 signature covers `enc`'s ASCII/UTF-8 bytes of the BASE64
/// STRING ITSELF, NOT the base64-decoded bytes. Get the byte source wrong
/// and every `.lic` file either fails verification (safe but broken) or,
/// worse, a bug that skips verification silently accepts forged files. See
/// the `CRITICAL:` comment at the call site in `verify(publicKey:)`.
///
/// GOTCHA: `includes` is always `[]` server-side -- this SDK does not model
/// an "embedded relationships via checkout" feature. GOTCHA: checkout `id`
/// is a fresh UUIDv7 per call, not idempotent. GOTCHA: `ttl`/`expiry`
/// (returned alongside the certificate by the JSON:API checkout response,
/// not carried inside the file itself) are metadata-only, NOT embedded in
/// the signed payload and NOT re-checked server-side on later validation --
/// expiry enforcement for an offline file is entirely this SDK's
/// client-side responsibility.
public struct LicenseFile: Sendable {
    private static let beginMarker = "-----BEGIN LICENSE FILE-----"
    private static let endMarker = "-----END LICENSE FILE-----"

    /// The parsed, unverified `{enc, sig, alg}` certificate.
    let certificate: LicenseFileCertificate

    private init(certificate: LicenseFileCertificate) {
        self.certificate = certificate
    }

    /// Parses a PEM-wrapped `.lic` file. Does NOT verify the signature --
    /// call `verify(publicKey:)` or `verifyAndDecrypt(publicKey:licenseKey:)`
    /// separately.
    public static func parse(_ pem: String) throws -> LicenseFile {
        let inner = try PemEnvelope.strip(pem, beginMarker: beginMarker, endMarker: endMarker)
        guard let jsonBytes = Data(base64Encoded: inner) else {
            throw TamgaCheckoutError.offlineFileFormat("License file body is not valid base64.")
        }

        let certificate: LicenseFileCertificate
        do {
            certificate = try TamgaJSONCoding.decoder.decode(LicenseFileCertificate.self, from: jsonBytes)
        } catch {
            throw TamgaCheckoutError.offlineFileFormat("License file certificate JSON is malformed: \(error)")
        }

        return LicenseFile(certificate: certificate)
    }

    /// Verifies the Ed25519 signature against the account's raw 32-byte
    /// Ed25519 public key. Returns `true`/`false` rather than throwing on a
    /// verification failure specifically -- callers that need a fail-closed
    /// exception should use `verifyAndDecrypt(publicKey:licenseKey:)`.
    ///
    /// - Throws: `TamgaCheckoutError.unsupportedAlgorithm` if `alg` does not
    ///   contain `"ed25519"`.
    public func verify(publicKey: Data) throws -> Bool {
        // Exact match against the two documented literal values (see
        // type-level remarks) rather than substring matching -- unlike
        // MachineFile's `alg`, which is a compound
        // encryption-prefix/signature-suffix string across 5 schemes,
        // LicenseFile's `alg` is always ed25519 and always one of exactly
        // these two literals, so exact equality is both correct and
        // stricter.
        guard certificate.alg == "base64+ed25519" || certificate.alg == "aes-256-gcm+ed25519" else {
            throw TamgaCheckoutError.unsupportedAlgorithm(
                "Unsupported license file algorithm: '\(certificate.alg)'. " +
                "Only ed25519-signed license files are supported."
            )
        }

        guard let signature = Data(base64Encoded: certificate.sig) else {
            return false
        }

        // CRITICAL: sign/verify over `enc`'s base64 STRING bytes (UTF-8 of
        // the string itself), NOT the base64-decoded payload bytes. This is
        // the single most consequential correctness trap in this SDK -- see
        // type-level remarks above.
        let message = Data(certificate.enc.utf8)
        return Ed25519.verify(publicKey: publicKey, message: message, signature: signature)
    }

    /// Full verify pipeline: verifies the Ed25519 signature (fails closed),
    /// then decrypts (if `alg` indicates AES-256-GCM) or plain-decodes the
    /// `enc` payload, and parses the embedded `{"data": <LicenseResource>}`
    /// JSON into a `License`.
    ///
    /// - Parameter licenseKey: used to derive the AES-256-GCM key (via
    ///   `NaiveKey`) for an encrypted file. Ignored for a plain (unencrypted)
    ///   file, but still required by this method's signature for a uniform
    ///   call shape across both cases.
    public func verifyAndDecrypt(publicKey: Data, licenseKey: String) throws -> License {
        guard try verify(publicKey: publicKey) else {
            throw TamgaCheckoutError.signatureVerificationFailed
        }

        guard let payloadBytes = Data(base64Encoded: certificate.enc) else {
            throw TamgaCheckoutError.offlineFileFormat("License file 'enc' is not valid base64.")
        }

        let jsonBytes: Data
        switch certificate.alg {
        case "aes-256-gcm+ed25519":
            jsonBytes = try Self.decryptPayload(payloadBytes, licenseKey: licenseKey)
        case "base64+ed25519":
            jsonBytes = payloadBytes
        default:
            // Defensive: unreachable in practice since `verify(publicKey:)`
            // above already validated `alg` is one of these two exact
            // literals and this method throws immediately if that fails --
            // kept as an explicit fail-closed branch rather than relying on
            // that ordering never changing.
            throw TamgaCheckoutError.unsupportedAlgorithm("Unsupported license file algorithm: '\(certificate.alg)'.")
        }

        let payload: JSONAPIPayload<LicenseAttributes>
        do {
            payload = try TamgaJSONCoding.decoder.decode(JSONAPIPayload<LicenseAttributes>.self, from: jsonBytes)
        } catch {
            throw TamgaCheckoutError.offlineFileFormat("License file payload JSON is malformed: \(error)")
        }

        return License.fromResource(payload.data)
    }

    private static func decryptPayload(_ payloadBytes: Data, licenseKey: String) throws -> Data {
        // CRITICAL: not a KDF -- see NaiveKey.swift. Zero-pad/truncate
        // transform of the raw license key string, exactly as the server
        // derives its own AES key for this format.
        let key = NaiveKey.derive(licenseKey: licenseKey)
        return try EncryptedPayloadDecryptor.decrypt(payloadBytes, key: key, context: "Encrypted license file")
    }
}
