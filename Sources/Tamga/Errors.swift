/// `Errors.swift`
///
/// STUB -- scaffolding only. No error model implemented yet.
///
/// Intended contents once implemented:
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
