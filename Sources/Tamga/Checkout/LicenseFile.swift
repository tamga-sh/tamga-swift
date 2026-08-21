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
    /// Algorithm identifier -- exactly `"base64+ed25519+v2"` (plain) or
    /// `"aes-256-gcm+ed25519+v2"` (encrypted).
    let alg: String
}

/// Parses, verifies, and decrypts an offline `.lic` license file:
/// ```
/// -----BEGIN LICENSE FILE-----
/// <base64 of JSON: { "enc": "<base64>", "sig": "<base64 ed25519 sig>", "alg": "..." }>
/// -----END LICENSE FILE-----
/// ```
///
/// The `+v2` suffix is load-bearing: a v1 file carried no expiry inside its
/// signature, so accepting one would hand back the permanent-file problem v2
/// exists to close.
///
/// `alg` is exactly `"base64+ed25519+v2"` (plain) or `"aes-256-gcm+ed25519+v2"`
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
/// is a fresh UUIDv7 per call, not idempotent. GOTCHA: the `ttl`/`expiry`
/// fields on the JSON:API checkout response *envelope* are metadata only --
/// whoever holds the file can drop the envelope, and the server does not
/// re-check them on later validation. The expiry that matters is the signed
/// `exp` claim inside the file (`LicenseFileClaims`), which format v2 added
/// and `verifyWithClaims(publicKey:licenseKey:now:)` enforces; enforcing it
/// is entirely this SDK's client-side responsibility.
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
        try validateAlgorithm()

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

    /// Rejects an `alg` this type cannot verify, before any key is looked at.
    ///
    /// Exact match against the two documented literal values (see type-level
    /// remarks) rather than substring matching -- unlike MachineFile's `alg`,
    /// which is a compound encryption-prefix/signature-suffix string across 5
    /// schemes, LicenseFile's `alg` is always ed25519 and always one of exactly
    /// these two literals, so exact equality is both correct and stricter.
    ///
    /// Split out of `verify(publicKey:)` so the key-set path can raise a bad
    /// `alg` once, up front, instead of once per candidate key.
    func validateAlgorithm() throws {
        guard certificate.alg == "base64+ed25519+v2" || certificate.alg == "aes-256-gcm+ed25519+v2" else {
            throw TamgaCheckoutError.unsupportedAlgorithm(
                "Unsupported license file algorithm: '\(certificate.alg)'. " +
                "Only ed25519-signed license files are supported."
            )
        }
    }

    /// Full verify pipeline: verifies the Ed25519 signature (fails closed),
    /// then decrypts (if `alg` indicates AES-256-GCM) or plain-decodes the
    /// `enc` payload, parses the embedded `{"data": <LicenseResource>}` JSON
    /// into a `License`, and enforces the signed `exp` claim against the
    /// system clock. Use `verifyWithClaims(publicKey:licenseKey:now:)` to
    /// supply a trusted timestamp instead, or to read the claims back.
    ///
    /// - Parameter licenseKey: used to derive the AES-256-GCM key (via
    ///   `Hkdf.deriveLicenseFileKey`) for an encrypted file. Ignored for a
    ///   plain (unencrypted) file, but still required by this method's
    ///   signature for a uniform call shape across both cases.
    /// - Throws: `TamgaCheckoutError.signatureVerificationFailed`,
    ///   `.expired(_:)`, `.decryptionFailed(_:)`, `.unsupportedAlgorithm(_:)`
    ///   or `.offlineFileFormat(_:)` -- never a successfully-returned
    ///   unverified `License`.
    public func verifyAndDecrypt(publicKey: Data, licenseKey: String) throws -> License {
        try verifyWithClaims(
            publicKey: publicKey,
            licenseKey: licenseKey,
            now: Int64(Date().timeIntervalSince1970)
        ).license
    }

    /// How much clock skew is tolerated when checking `exp`.
    ///
    /// Deliberately small. The client's clock is under the attacker's control,
    /// so a generous allowance is just a free extension on every expired file;
    /// this covers ordinary NTP drift and nothing more.
    static let clockSkewToleranceSeconds: Int64 = 60

    /// As `verifyAndDecrypt(publicKey:licenseKey:)`, also returning the signed
    /// claims and taking the current time from the caller.
    ///
    /// Two uses for `now`. Tests get determinism. And an application that keeps
    /// a server-supplied timestamp -- the recommended defence against a user
    /// winding the system clock back to revive an expired file -- can pass that
    /// instead of trusting the local clock.
    ///
    /// Expiry is enforced either way; it is not opt-in.
    public func verifyWithClaims(
        publicKey: Data,
        licenseKey: String,
        now: Int64
    ) throws -> (license: License, claims: LicenseFileClaims) {
        guard try verify(publicKey: publicKey) else {
            throw TamgaCheckoutError.signatureVerificationFailed
        }

        guard let payloadBytes = Data(base64Encoded: certificate.enc) else {
            throw TamgaCheckoutError.offlineFileFormat("License file 'enc' is not valid base64.")
        }

        let jsonBytes: Data
        switch certificate.alg {
        case "aes-256-gcm+ed25519+v2":
            jsonBytes = try Self.decryptPayload(payloadBytes, licenseKey: licenseKey)
        case "base64+ed25519+v2":
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

        // Second line behind the alg gate: a file must not reach the expiry
        // check with nothing to check.
        guard let claims = payload.meta else {
            throw TamgaCheckoutError.offlineFileFormat(
                "License file payload is missing the signed 'meta' claims (this looks like a pre-v2 file)."
            )
        }

        // The signature proves the file is authentic. It does not prove it is
        // still valid -- that is this check, and skipping it is what made v1
        // files permanent.
        if let exp = claims.exp, now - Self.clockSkewToleranceSeconds > exp {
            throw TamgaCheckoutError.expired(exp)
        }

        return (License.fromResource(payload.data), claims)
    }

    /// The signed claims, read **without** verifying the signature.
    ///
    /// Diagnostic only, and used from exactly one place: after every key in a
    /// caller-supplied key set has failed to verify this file, the `kid` claim
    /// is the only thing that separates "signed by a key I do not have" from
    /// "forged". Returns `nil` rather than throwing for every failure -- a
    /// wrong licence key, a corrupt payload, a pre-v2 file with no claims --
    /// because at that point the caller gets
    /// `TamgaCheckoutError.signatureVerificationFailed` either way.
    ///
    /// Nothing else in this type reads unverified bytes, and nothing derived
    /// from these claims is ever returned to a caller as a `License`.
    func unverifiedClaims(licenseKey: String) -> LicenseFileClaims? {
        guard let payloadBytes = Data(base64Encoded: certificate.enc) else { return nil }
        let jsonBytes: Data
        if certificate.alg == "aes-256-gcm+ed25519+v2" {
            guard let decrypted = try? Self.decryptPayload(payloadBytes, licenseKey: licenseKey) else {
                return nil
            }
            jsonBytes = decrypted
        } else {
            jsonBytes = payloadBytes
        }
        return try? TamgaJSONCoding.decoder
            .decode(JSONAPIPayload<LicenseAttributes>.self, from: jsonBytes).meta
    }

    static func decryptPayload(_ payloadBytes: Data, licenseKey: String) throws -> Data {
        let key = Hkdf.deriveLicenseFileKey(licenseKey: licenseKey)
        // Concatenated, NOT dot-separated: `encode_license_file` base64s a
        // single `nonce ‖ ciphertext ‖ tag` buffer, where the machine-file
        // encoder delegates to `FieldEncryption::encrypt` and gets two
        // separately-base64'd halves. Verified against both server encoders --
        // the two file types really do differ here.
        return try EncryptedPayloadDecryptor.decryptConcatenated(
            payloadBytes, key: key, context: "Encrypted license file"
        )
    }
}
