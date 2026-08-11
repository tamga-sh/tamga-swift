/// `MachineFile.swift`
///
/// STUB -- scaffolding only. No implementation yet.
///
/// Offline machine file (`.machine`) parse/verify/decrypt -- docs/sdk.md §6.
/// security-reviewer pass is MANDATORY before this section is marked done
/// (see docs/plans/tamga-swift.plan.md Section G).
///
/// Same PEM-wrapped `{enc, sig, alg}` shape as `LicenseFile.swift`, wrapped
/// in `-----BEGIN MACHINE FILE-----` / `-----END MACHINE FILE-----` markers,
/// with two key differences from license checkout:
///
/// - Signing scheme is taken from the LICENSE's `scheme` field (Ed25519,
///   RSA-PKCS1, RSA-PSS, or ECDSA-P256 -- see `Policy.swift`'s
///   `LicenseScheme`), NOT hardcoded to Ed25519 like license checkout.
///   Dispatch to `Sources/Tamga/FFI/MultiSchemeVerifier.swift` per scheme.
///   `RSA_2048_JWT_RS256` is explicitly rejected server-side
///   (`422 SCHEME_NOT_SUPPORTED`) -- guard against it client-side too, before
///   the request, if the caller has a cached scheme value.
/// - Encryption key derivation (when encrypted) is a REAL HKDF-SHA256 --
///   unlike license checkout's naive zero-pad/truncate transform:
///   `salt="tamga:machine-file-key-v1"`, `ikm=<license key>`,
///   `info=<machine fingerprint>` -> 32-byte AES key. Delegates to
///   `Sources/Tamga/FFI/HkdfDeriver.swift`. Decrypting a machine file
///   therefore requires BOTH the license key AND the target machine's
///   fingerprint -- the public API must require both.
///
/// `ttl` is server-validated `> 0 && <= 31536000` (365 days) --
/// `422 TTL_INVALID` otherwise; validate client-side too, to fail fast
/// rather than round-trip a guaranteed rejection.
///
/// Intended public API:
///   `MachineFile.verify(publicKey:scheme:) throws -> Machine`
///   `MachineFile.verifyAndDecrypt(publicKey:scheme:licenseKey:fingerprint:) throws -> Machine`
public enum MachineFile {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Section G.
}
