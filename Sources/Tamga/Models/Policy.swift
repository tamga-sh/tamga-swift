/// `Policy.swift`
///
/// The key/checkout signing algorithm configured on a license's policy.
/// `.none` means the policy has no scheme set -- a legacy plain key string,
/// unsigned.
public enum LicenseScheme: String, Equatable, Sendable {
    /// No scheme configured -- legacy plain key string, unsigned.
    case none = ""
    /// Wire value `ED25519_SIGN`. Also the sole scheme used for license
    /// checkout (`Checkout/LicenseFile.swift`), independent of this field.
    case ed25519Sign = "ED25519_SIGN"
    /// Wire value `RSA_2048_PKCS1_SIGN`.
    case rsa2048Pkcs1Sign = "RSA_2048_PKCS1_SIGN"
    /// Wire value `RSA_2048_PKCS1_PSS_SIGN`.
    case rsa2048Pkcs1PssSign = "RSA_2048_PKCS1_PSS_SIGN"
    /// Wire value `ECDSA_P256_SIGN`.
    case ecdsaP256Sign = "ECDSA_P256_SIGN"
    /// Wire value `RSA_2048_JWT_RS256`. Explicitly rejected server-side for
    /// machine files (`422 SCHEME_NOT_SUPPORTED`) -- `MachineFile` must throw
    /// rather than attempt JWT/RS256 verification.
    case rsa2048JwtRs256 = "RSA_2048_JWT_RS256"

    /// An empty string or missing value maps to `.none` (legacy unsigned key).
    public init(wireValue: String?) {
        self = LicenseScheme(rawValue: wireValue ?? "") ?? .none
    }
}

/// STUB -- scaffolding only beyond `LicenseScheme` above.
///
/// Intended contents once implemented:
///
/// - `Policy`: full attribute set (`max_machines`, `max_cores`,
///   `max_processes`, `max_uses`, `require_check_in`, `heartbeat_duration`,
///   `overage_strategy`, `heartbeat_cull_strategy`,
///   `heartbeat_resurrection_strategy`, `expiration_strategy`,
///   `renewal_basis`, `authentication_strategy`, `check_in_interval`,
///   `scheme`). NOTE: `GET` on a policy omits `max_memory` and `max_disk`
///   even though both are enforced during validation -- the SDK cannot
///   introspect these two limits client-side, only observe
///   `TOO_MUCH_MEMORY`/`TOO_MUCH_DISK` on validation failure.
/// - `OverageStrategy` enum: `NO_OVERAGE` (x1), `ALLOW_1_25X_OVERAGE`,
///   `ALLOW_1_5X_OVERAGE`, `ALLOW_2X_OVERAGE`, `ALWAYS_ALLOW_OVERAGE` (limit
///   ignored). Applies to machines/cores/memory/disk/processes -- NEVER to
///   `uses` (strict `>=` regardless of strategy).
/// - `HeartbeatCullStrategy` enum: `DEACTIVATE_DEAD`, `KEEP_DEAD`.
/// - `HeartbeatResurrectionStrategy` enum: `NO_REVIVE`, `1_MINUTE_REVIVE`,
///   `2_MINUTE_REVIVE`, `5_MINUTE_REVIVE`, `10_MINUTE_REVIVE`,
///   `15_MINUTE_REVIVE`, `ALWAYS_REVIVE`.
/// - Free-text fields with NO backing server enum -- model as Swift enums
///   with an explicit deny-leaning fallback case, branched by literal string
///   match, not a closed set:
///     - `expirationStrategy`: `"RESTRICT_ACCESS"` (default) /
///       `"MAINTAIN_ACCESS"` / `"ALLOW_ACCESS"`.
///     - `renewalBasis`: `"FROM_EXPIRY"` (default) / `"FROM_NOW"`.
///     - `authenticationStrategy`: `"TOKEN"` (default) / `"LICENSE"` /
///       `"MIXED"`.
///     - `checkInInterval`: lowercase (inconsistent with the SCREAMING_SNAKE
///       enums above) -- `"day"` / `"week"` / `"month"` / `"year"`.
///
/// CRITICAL TRAP:
/// freshly-created policies default `overage_strategy` to the literal string
/// `"DENY_ACCESS"` and `heartbeat_resurrection_strategy` to
/// `"NO_RESURRECTION"` -- NEITHER is a real enum variant. The server silently
/// treats them as `NO_OVERAGE` / `NO_REVIVE` respectively. The decoders here
/// must not crash on these strings, and must NOT invent a fake
/// `DENY_ACCESS`/`NO_RESURRECTION` case that implies restrictive behavior the
/// server doesn't actually have -- decode to a documented
/// "unrecognized, behaves as NO_OVERAGE/NO_REVIVE" fallback instead.
public enum Policy {
    // Intentionally empty beyond LicenseScheme above, which the checkout
    // architecture pivot needed for MachineFile's scheme dispatch.
    // Implementation deferred to a future release.
}
