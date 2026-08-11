/// `LicenseFile.swift`
///
/// STUB -- scaffolding only. No implementation yet.
///
/// Offline license file (`.lic`) parse/verify/decrypt -- docs/sdk.md §4. This
/// is the highest-stakes file in the whole SDK; security-reviewer pass is
/// MANDATORY before this section is marked done (see
/// docs/plans/tamga-swift.plan.md Section F).
///
/// File format: PEM-style wrapper
/// `-----BEGIN LICENSE FILE-----` / `-----END LICENSE FILE-----` around
/// base64 of `{ "enc": "<base64>", "sig": "<base64 ed25519 sig>",
/// "alg": "<algorithm string>" }`.
///
/// `alg` is always exactly `"base64+ed25519"` (plain) or
/// `"aes-256-gcm+ed25519"` (encrypted) -- Ed25519 ONLY for the checkout
/// signature, independent of the license's own key `scheme`.
///
/// Intended verification flow, EXACT order (crypto delegates to
/// `Sources/Tamga/FFI/Ed25519Verifier.swift` and
/// `Sources/Tamga/FFI/AesGcmCipher.swift` -- this file stays pure Swift):
///
///   1. Strip PEM markers, base64-decode the outer envelope.
///   2. Parse the resulting `{enc, sig, alg}` JSON.
///   3. Base64-decode `sig`.
///   4. CRITICAL: Ed25519-verify `sig` against `enc`'s ASCII/UTF-8 bytes OF
///      THE BASE64 STRING ITSELF -- NOT the decoded bytes. This is the
///      single most common implementation bug in the entire spec.
///   5. Base64-decode `enc` to get the actual payload bytes.
///   6. If `alg` contains `"aes-256-gcm"`: split nonce(12B)/ciphertext+tag
///      (16B tag) and AES-256-GCM-open using the license-key-derived key.
///   7. Parse the resulting bytes as `{"data": <LicenseResource>}` JSON.
///
/// CRITICAL: the AES key (when encrypted) is the license key's raw UTF-8
/// bytes, zero-padded or truncated to exactly 32 bytes -- this is NOT a hash
/// or KDF. A verifier that runs the key through SHA-256 or any other KDF
/// will silently produce the wrong key and fail to decrypt.
///
/// `includes` is always `[]` today -- do not build a "checkout with embedded
/// relationships" feature around it. `id` is a fresh UUIDv7 per call, not
/// idempotent -- two checkout calls yield two different certificates.
/// `ttl`/`expiry` are metadata only, NOT embedded in the signed payload and
/// NOT re-checked server-side on any later validation -- offline-file expiry
/// enforcement is entirely this SDK's client-side responsibility.
///
/// Intended public API:
///   `LicenseFile.verify(publicKey:) throws -> License`
///   `LicenseFile.verifyAndDecrypt(publicKey:licenseKey:) throws -> License`
public enum LicenseFile {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Section F.
}
