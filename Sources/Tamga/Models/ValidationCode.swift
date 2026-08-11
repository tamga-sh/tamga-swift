/// `ValidationCode.swift`
///
/// STUB -- scaffolding only. No implementation yet.
///
/// Intended contents once implemented: a `ValidationCode` enum modeling all 24
/// wire values of `meta.code` from docs/sdk.md §2, with lenient decoding (an
/// `.unknown(String)` fallback case for any value not in the known set --
/// never crash on an unrecognized code).
///
/// Only 14 of the 24 values are actually reachable against the server today;
/// the other 10 are declared in the server's enum but never emitted by any
/// code path (see docs/sdk.md's "Known Server-Side Gaps" item 4). Model all
/// 24 for forward-compatibility, but doc-comment the unreachable ones so
/// callers don't build UX assuming they'll ever see them:
///
/// Reachable today (✅): VALID, SUSPENDED, EXPIRED, OVERDUE,
/// PRODUCT_SCOPE_MISMATCH, POLICY_SCOPE_MISMATCH, USER_SCOPE_MISMATCH,
/// ENVIRONMENT_SCOPE_MISMATCH, TOO_MANY_MACHINES, TOO_MANY_CORES,
/// TOO_MUCH_MEMORY, TOO_MUCH_DISK, TOO_MANY_PROCESSES, TOO_MANY_USES.
///
/// Not reachable yet (⛔): NOT_FOUND (handler returns HTTP 404 directly
/// instead), BANNED, ENTITLEMENTS_MISSING, TOO_MANY_USERS, HEARTBEAT_DEAD,
/// HEARTBEAT_NOT_STARTED, FINGERPRINT_SCOPE_MISMATCH,
/// COMPONENTS_SCOPE_MISMATCH, CHECKSUM_SCOPE_MISMATCH,
/// VERSION_SCOPE_MISMATCH.
public enum ValidationCode {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Section D.
}
