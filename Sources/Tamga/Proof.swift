/// `Proof.swift`
///
/// STUB -- scaffolding only. No implementation yet.
///
/// Machine offline proof (air-gapped verification) -- docs/sdk.md §7.
///
/// Intended contents once implemented (crypto delegates to
/// `Sources/Tamga/FFI/MultiSchemeVerifier.swift`, which in turn wraps
/// `tamga-c`'s RSA verify primitive -- this file itself must stay pure Swift):
///
/// - `generateOfflineProof(machineId:dataset:)`: calls
///   `POST /machines/{id}/actions/generate-offline-proof` with body
///   `{ "meta": { "dataset": {...} } }` (defaults to `{}`).
/// - ALWAYS signs with RSA-2048 PKCS#1 v1.5 / SHA-256, regardless of the
///   license's `scheme` -- unlike machine checkout, there is no scheme
///   dispatch here.
/// - Response parsing for the versioned-prefix proof string:
///   `meta.proof = "v1x0.<base64 signature>"`.
/// - A custom ORDERED-KEY JSON encoder (NOT `JSONEncoder`'s unordered
///   dictionary output) that reproduces the server's exact serialization of
///   `{"account":{"id":...},"machine":{"id":...,"fingerprint":...},
///   "dataset":<client dataset>}` byte-for-byte -- field order matters, or
///   signature verification fails.
/// - Public verifier API:
///   `MachineProof.verify(publicKey:machine:dataset:) throws -> Bool`.
///
/// CRITICAL: the ordered-serialization requirement is the same class of bug
/// as the base64-string-vs-decoded-bytes trap in `Checkout/LicenseFile.swift`
/// -- a functionally "equivalent" JSON payload with different key order will
/// fail server-side verification. security-reviewer pass is MANDATORY on this
/// file per docs/plans/tamga-swift.plan.md Section I before it is considered
/// done.
public enum MachineProof {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Section I.
}
