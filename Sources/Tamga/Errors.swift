import Foundation

/// `Errors.swift`
///
/// **Scope note**: `TamgaCheckoutError` below covers exactly the failure
/// modes `Checkout/LicenseFile.swift`, `Checkout/MachineFile.swift`, and
/// `Proof.swift` can throw. The full JSON:API error envelope decoder (401/
/// 403/404/409/500 handling, per-endpoint conflict/validation codes) for
/// `TamgaClient`'s HTTP-facing surface is still deferred to a future session
/// per `docs/plans/tamga-swift.plan.md` Section L -- see that section's
/// intended `TamgaError` shape below, unchanged from before this file had
/// any real implementation.
///
/// Intended contents once implemented (HTTP-facing surface):
///
/// - `TamgaError`: models the JSON:API error object
///   `{ status: UInt16, code: String, detail: String, pointer: String? }`.
///   Callers must match on `code` (stable, server-documented) and never on
///   `detail` (human-readable text that may change without notice).
/// - Fixed-status cases: `.notFound` (404), `.unauthorized` (401),
///   `.forbidden` (403), `.internalServerError` (500 -- generic, never leaks
///   DB detail server-side).
/// - Per-endpoint conflict codes (409): `.keyTaken`, `.fingerprintTaken`,
///   `.pidTaken`.
/// - Per-endpoint validation codes (422): `.checkInNotRequired`, `.ttlInvalid`,
///   `.licenseNotEncrypted`, `.licenseKeyMissing`, `.schemeNotSupported`,
///   `.datasetInvalid`.
/// - A `.unknown(status:code:detail:pointer:)` fallback case for any `code`
///   not in the known set -- decoding must never crash on an unrecognized
///   server error code.
/// - A JSON:API error envelope decoder:
///   `{"errors": [{ id, status, code, title, detail, source: { pointer } }]}`.
///
/// Explicitly NOT modeled as a retryable/backoff case: `429 TOO_MANY_REQUESTS`
/// is declared in the server's error enum but has no constructor and is never
/// returned by any code path today (see docs/sdk.md's "Known Server-Side
/// Gaps"). Do not build client-side 429/backoff handling expecting the server
/// to ever send it under the current deployment.
public enum TamgaError {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Section L.
}

/// Errors thrown by `Checkout/LicenseFile.swift`, `Checkout/MachineFile.swift`,
/// and `Proof.swift`. Distinct from the (still-deferred) HTTP-facing
/// `TamgaError` above -- these describe failures in parsing/verifying/
/// decrypting an already-issued offline file or proof, not a live API call.
public enum TamgaCheckoutError: Error, Equatable {
    /// The PEM envelope or inner JSON is malformed.
    case offlineFileFormat(String)
    /// Signature verification failed -- the file may be forged or corrupted.
    case signatureVerificationFailed
    /// The certificate's `alg` field, or a caller-supplied scheme, isn't
    /// recognized.
    case unsupportedAlgorithm(String)
    /// `RSA_2048_JWT_RS256` (or any other scheme never implemented for a
    /// given file type) was requested explicitly.
    case schemeNotSupported(String)
    /// Client-side mirror of the server's `422 TTL_INVALID`: `ttl` must be
    /// `> 0 && <= 31536000` (365 days).
    case ttlInvalid(String)
}
