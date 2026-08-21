import Foundation

/// The inner `{enc, sig, alg}` JSON structure carried inside a `.machine`
/// file's PEM envelope -- same shape as `LicenseFileCertificate`.
struct MachineFileCertificate: Decodable {
    /// The payload. For a plain file, base64 of the payload JSON. For an
    /// encrypted file, `"<nonce_b64>.<cipher_b64>"` -- two SEPARATELY
    /// base64-encoded halves, so the whole string is not itself valid base64.
    /// Which one it is comes from `alg`'s encoding prefix, never from whether
    /// a `.` happens to be present.
    let enc: String
    /// The signature over `enc`'s string bytes, base64-encoded. Covers `enc`
    /// and nothing else -- `alg` and `sig` are outside it.
    let sig: String
    /// The algorithm identifier: `"<encoding>+<signing suffix>+v2"`. Parsed by
    /// `MachineFileAlgorithm`, which also explains why it is parsed rather
    /// than substring-matched. NEVER used to select the verifier -- see
    /// `MachineFile`'s type-level remarks.
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
/// Like a license file, a machine file IS subject to the `+v2` `alg` check and
/// DOES carry signed `meta` claims. Both statements were once false and the
/// doc comment they replace asserted the opposite: `check_out_machine.rs` now
/// signs `{"data": <machine>, "meta": {iat, exp, jti, kid}}`, and
/// `machine_file_alg_str` now appends a mandatory `+v2`. A verifier that reads
/// neither accepts a v1 file and lets an expired machine file verify forever,
/// which is what this type used to do.
///
/// `exp` is optional by design: `check_out_machine.rs` sets it from `ttl`, and
/// a checkout made without a `ttl` produces a file with no `exp` that
/// genuinely never expires. Absence is legitimate and is not an error.
/// Presence is enforced, against the same 60-second skew tolerance the license
/// file path uses (`LicenseFile.clockSkewToleranceSeconds` -- one constant, so
/// the two file types cannot drift into different grace periods).
///
/// GOTCHA: `ttl` is server-validated `> 0 && <= 31536000` (365
/// days) -- the SDK's checkout call validates this client-side too, to fail
/// fast, in addition to handling the server's `422 TTL_INVALID`.
///
/// Pass the public key exactly as the server's account resource publishes it.
/// Ed25519 is 32 raw bytes; ECDSA P-256 is the 65-byte uncompressed X9.63
/// point; RSA is PKCS#1 `RSAPublicKey` DER. X.509 `SubjectPublicKeyInfo` is
/// also accepted for both RSA and ECDSA, so a caller who already normalised to
/// SPKI is not broken by this. The ECDSA case is not a convenience: requiring
/// SPKI there meant no genuine ECDSA machine file could be verified at all --
/// see `Crypto/Ecdsa.swift`.
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

    /// Checks the file's self-declared `alg` and returns it parsed.
    ///
    /// Two separate jobs, in this order:
    ///
    /// 1. Refuse `.rsa2048JwtRs256` outright, before the string is even looked
    ///    at. It has no verifiable machine-file form at all.
    /// 2. Parse `alg` -- which rejects a missing `+v2` marker and an
    ///    unrecognised encoding prefix -- then check the signing suffix it
    ///    declares against the suffix the server emits for `scheme`.
    ///
    /// Step 2 is a CROSS-CHECK, not dispatch. `scheme` still decides which
    /// verifier runs, and `scheme` comes from the caller's own license record;
    /// the file gets a veto over a mismatch and no say beyond that. The
    /// distinction is load-bearing: `RSA_2048_PKCS1_SIGN` and
    /// `RSA_2048_JWT_RS256` produce the identical `rsa-sha256` suffix, so a
    /// verifier that read the scheme out of `alg` could not tell them apart.
    func validatedAlgorithm(scheme: LicenseScheme) throws -> MachineFileAlgorithm {
        guard let expectedSuffix = MachineFileAlgorithm.signingSuffix(for: scheme) else {
            throw TamgaCheckoutError.schemeNotSupported(
                "RSA_2048_JWT_RS256 is rejected server-side for machine files (422 SCHEME_NOT_SUPPORTED) " +
                "and is not implemented client-side either -- this SDK never attempts JWT/RS256 verification."
            )
        }

        let algorithm = try MachineFileAlgorithm.parse(certificate.alg)

        guard algorithm.signingSuffix == expectedSuffix else {
            throw TamgaCheckoutError.unsupportedAlgorithm(
                "Machine file algorithm '\(certificate.alg)' declares signing suffix " +
                "'\(algorithm.signingSuffix)', but the license's scheme (\(scheme.rawValue)) is signed as " +
                "'\(expectedSuffix)'. The scheme, not the file, decides which verifier runs -- so a file that " +
                "disagrees with it is refused rather than verified under either."
            )
        }

        return algorithm
    }

    /// Verifies the signature against the account's public key, dispatching
    /// by the caller-supplied `scheme` -- NEVER by parsing this file's own
    /// `alg` string. See type-level remarks for the algorithm-confusion
    /// rationale.
    ///
    /// - Throws: `TamgaCheckoutError.schemeNotSupported` if `scheme` is
    ///   `.rsa2048JwtRs256` -- never implemented for machine files;
    ///   `.unsupportedAlgorithm` if `alg` is not a well-formed v2 machine-file
    ///   algorithm string, or names a different signing algorithm than
    ///   `scheme`.
    public func verify(scheme: LicenseScheme, publicKey: Data) throws -> Bool {
        _ = try validatedAlgorithm(scheme: scheme)
        return verifySignature(scheme: scheme, publicKey: publicKey)
    }

    /// The signature check on its own, with `alg` already validated by the
    /// caller. Split out so `verifyWithClaims` can hold the parsed algorithm
    /// it needs for the payload branch without parsing twice.
    func verifySignature(scheme: LicenseScheme, publicKey: Data) -> Bool {
        guard let signature = Data(base64Encoded: certificate.sig) else {
            return false
        }
        // CRITICAL: the signature covers `enc`'s STRING bytes, not its decoded
        // bytes -- the same trap `LicenseFile` documents at length. It also
        // covers only `enc`: `alg` and `sig` are outside it, which is why
        // `validatedAlgorithm` exists.
        let message = Data(certificate.enc.utf8)

        switch scheme {
        case .rsa2048JwtRs256:
            // Unreachable: `validatedAlgorithm` throws for this scheme before
            // any caller reaches here. Kept as an explicit fail-closed branch
            // rather than relying on that ordering never changing.
            return false
        case .none, .ed25519Sign:
            return Ed25519.verify(publicKey: publicKey, message: message, signature: signature)
        case .rsa2048Pkcs1Sign:
            return Rsa.verifyPkcs1(publicKeyDER: publicKey, message: message, signature: signature)
        case .rsa2048Pkcs1PssSign:
            return Rsa.verifyPss(publicKeyDER: publicKey, message: message, signature: signature)
        case .ecdsaP256Sign:
            return Ecdsa.verify(publicKey: publicKey, message: message, signature: signature)
        }
    }

    /// Full verify pipeline: verifies the signature (fails closed), then
    /// decrypts or plain-decodes the `enc` payload, parses the embedded
    /// `{"data": <MachineResource>, "meta": <claims>}` JSON, and enforces the
    /// signed `exp` claim against the system clock.
    ///
    /// Use `verifyWithClaims(scheme:publicKey:licenseKey:fingerprint:now:)` to
    /// supply a trusted timestamp instead of the local clock, or to read the
    /// claims back.
    ///
    /// - Parameter scheme: the license's signing scheme -- drives verifier
    ///   dispatch, see type-level remarks.
    /// - Parameter licenseKey: HKDF input keying material for an encrypted
    ///   file. Ignored for a plain file, but still required for a uniform call
    ///   shape across both.
    /// - Parameter fingerprint: the target machine's fingerprint -- HKDF
    ///   `info` for an encrypted file. Decryption fails closed (AES-GCM auth
    ///   failure) if this doesn't match the machine the file was issued for.
    ///
    ///   NOTE that this binds an ENCRYPTED file only. A plain machine file is
    ///   signed but not encrypted, so there is no key derivation to fail and
    ///   this argument goes unused on that path -- a plain file issued for
    ///   another machine will verify here. Its binding lives in the signed
    ///   payload's own `fingerprint` field, which is returned on the `Machine`
    ///   and which a caller accepting plain files must compare itself. The
    ///   SDK deliberately does not enforce the match: `tamga-go`'s
    ///   `MachineFile.Verify` behaves the same way, and making one SDK stricter
    ///   than the fleet would reject files the others accept.
    /// - Throws: `TamgaCheckoutError.signatureVerificationFailed`,
    ///   `.expired(_:)`, `.decryptionFailed(_:)`, `.unsupportedAlgorithm(_:)`,
    ///   `.schemeNotSupported(_:)` or `.offlineFileFormat(_:)` -- never a
    ///   successfully-returned unverified or expired `Machine`.
    public func verifyAndDecrypt(
        scheme: LicenseScheme, publicKey: Data, licenseKey: String, fingerprint: String
    ) throws -> Machine {
        try verifyWithClaims(
            scheme: scheme,
            publicKey: publicKey,
            licenseKey: licenseKey,
            fingerprint: fingerprint,
            now: Int64(Date().timeIntervalSince1970)
        ).machine
    }

    /// As `verifyAndDecrypt(scheme:publicKey:licenseKey:fingerprint:)`, also
    /// returning the signed claims and taking the current time from the caller.
    ///
    /// Two uses for `now`, both the same as the license-file path's. Tests get
    /// determinism. And an application that keeps a server-supplied timestamp
    /// -- the recommended defence against a user winding the system clock back
    /// to revive an expired file -- can pass that instead of trusting the local
    /// clock, which on an offline-verification path is by definition under the
    /// attacker's control.
    ///
    /// Expiry is enforced either way; it is not opt-in. `iat`, `jti` and `kid`
    /// come back unenforced, for a caller that wants replay detection (`jti`)
    /// or to reason about key rotation (`kid`).
    public func verifyWithClaims(
        scheme: LicenseScheme,
        publicKey: Data,
        licenseKey: String,
        fingerprint: String,
        now: Int64
    ) throws -> (machine: Machine, claims: LicenseFileClaims) {
        // Order is the security property here: validate `alg`, verify the
        // signature over the raw `enc` string, and only then interpret any
        // structure inside `enc`. Splitting, base64-decoding or decrypting
        // attacker-supplied bytes before the signature has passed hands an
        // attacker a parser to aim at.
        let algorithm = try validatedAlgorithm(scheme: scheme)

        guard verifySignature(scheme: scheme, publicKey: publicKey) else {
            throw TamgaCheckoutError.signatureVerificationFailed
        }

        let jsonBytes: Data
        switch algorithm.encoding {
        case .aes256Gcm:
            // NOT a single base64 blob with a 12-byte nonce sliced off the
            // front -- that is what this SDK did, and it could not open a
            // single encrypted machine file the server ever issued. See
            // `EncryptedPayloadDecryptor.decryptDotSeparated`.
            let key = Hkdf.deriveMachineFileKey(licenseKey: licenseKey, fingerprint: fingerprint)
            jsonBytes = try EncryptedPayloadDecryptor.decryptDotSeparated(
                certificate.enc, key: key, context: "Encrypted machine file"
            )
        case .base64:
            // Branch on the encoding prefix from `alg`, never on whether a `.`
            // happens to appear: base64's own alphabet excludes `.`, but
            // deciding by content would let the payload pick its own decoder.
            guard let payloadBytes = Data(base64Encoded: certificate.enc) else {
                throw TamgaCheckoutError.offlineFileFormat("Machine file 'enc' is not valid base64.")
            }
            jsonBytes = payloadBytes
        }

        let payload: JSONAPIPayload<MachineAttributes>
        do {
            payload = try TamgaJSONCoding.decoder.decode(JSONAPIPayload<MachineAttributes>.self, from: jsonBytes)
        } catch {
            throw TamgaCheckoutError.offlineFileFormat("Machine file payload JSON is malformed: \(error)")
        }

        // Second line behind the `+v2` gate: a file that got past the alg check
        // must not then reach the expiry check with nothing to check.
        guard let claims = payload.meta else {
            throw TamgaCheckoutError.offlineFileFormat(
                "Machine file payload is missing the signed 'meta' claims (this looks like a pre-v2 file)."
            )
        }

        // The signature proves the file is authentic. It does not prove it is
        // still valid -- that is this check. A missing `exp` is legitimate and
        // means the checkout carried no `ttl`; a present one is enforced.
        if let exp = claims.exp, now - LicenseFile.clockSkewToleranceSeconds > exp {
            throw TamgaCheckoutError.expired(exp)
        }

        return (Machine.fromResource(payload.data), claims)
    }

    /// The signed claims, read **without** verifying the signature.
    ///
    /// Diagnostic only. See `LicenseFile.unverifiedClaims(licenseKey:)` for
    /// the full rationale -- this is the machine-file half of the same thing,
    /// and the same rule applies: it is reached only once every key in a
    /// caller-supplied key set has already failed, its output picks an error
    /// label and nothing else, and no `Machine` is ever produced from it.
    func unverifiedClaims(
        algorithm: MachineFileAlgorithm, licenseKey: String, fingerprint: String
    ) -> LicenseFileClaims? {
        let jsonBytes: Data
        switch algorithm.encoding {
        case .aes256Gcm:
            let key = Hkdf.deriveMachineFileKey(licenseKey: licenseKey, fingerprint: fingerprint)
            guard let decrypted = try? EncryptedPayloadDecryptor.decryptDotSeparated(
                certificate.enc, key: key, context: "Encrypted machine file"
            ) else { return nil }
            jsonBytes = decrypted
        case .base64:
            guard let payloadBytes = Data(base64Encoded: certificate.enc) else { return nil }
            jsonBytes = payloadBytes
        }
        return try? TamgaJSONCoding.decoder
            .decode(JSONAPIPayload<MachineAttributes>.self, from: jsonBytes).meta
    }
}
