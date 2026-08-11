/// `License.swift`
///
/// STUB -- scaffolding only. No implementation yet.
///
/// Intended contents once implemented:
///
/// - `License`: full JSON:API resource attributes mirroring the server's
///   license resource shape (key, suspended, expiry, uses, etc. -- see
///   docs/sdk.md §2 and §10).
/// - `License.hasEntitlement(code:)`: convenience async helper that
///   fetches/caches the entitlement list (see `Entitlement.swift`) and
///   matches on `code` (the stable, developer-facing identifier), NOT `name`
///   (display label only).
/// - An in-memory entitlement cache with explicit invalidation -- no TTL
///   assumption baked in; the caller controls freshness.
public enum License {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Sections D and K.
}
