import Foundation

/// Optional constraints sent as `meta.scope` on a validate-by-id request.
///
/// Every field is optional; an unset field means "no constraint, skip this
/// check" and is omitted from the request body entirely rather than sent as
/// null -- the server treats a present key as a constraint to evaluate.
///
/// **Six of the eight fields are enforced server-side**: `product`, `policy`,
/// `user`, `environment`, `fingerprint` and `entitlements`. The last two used to
/// be parsed and ignored and are now genuinely checked.
///
/// The remaining two, `version` and `checksum`, are worse than ignored: the
/// server rejects the **entire validate call** with
/// `422 SCOPE_NOT_SUPPORTED` the moment either is present, so no verdict comes
/// back at all. This SDK therefore **no longer sends them**, which degrades a
/// caller that sets one to a working validate instead of a hard failure. Both
/// properties are kept so existing code still compiles.
public struct Scope: Equatable, Sendable {
    /// Enforced server-side.
    public var product: String?
    /// Enforced server-side.
    public var policy: String?
    /// Enforced server-side.
    public var user: String?
    /// Enforced server-side.
    public var environment: String?
    /// **Enforced server-side.** Matches against any machine row on the licence,
    /// regardless of that machine's heartbeat status. A mismatch reports
    /// `FINGERPRINT_SCOPE_MISMATCH` -- this is the anti-key-sharing check, and
    /// it works now.
    public var fingerprint: String?
    /// **Deprecated and no longer sent.** Present on the request it would draw
    /// `422 SCOPE_NOT_SUPPORTED` and sink the whole validate call, so this SDK
    /// omits it from the body.
    public var version: String?
    /// **Deprecated and no longer sent.** Same `422 SCOPE_NOT_SUPPORTED`
    /// rejection as `version`.
    public var checksum: String?
    /// **Enforced server-side.** Takes entitlement **codes** -- the stable
    /// developer-facing identifiers, not the UUIDs used by attach/detach.
    /// Comparison is case-insensitive and de-duplicated, and the check is
    /// satisfied by directly attached and policy-inherited entitlements alike.
    /// An empty array asserts nothing. A shortfall reports
    /// `ENTITLEMENTS_MISSING`.
    public var entitlements: [String]?

    /// Creates a scope. Every constraint defaults to unset.
    public init(
        product: String? = nil,
        policy: String? = nil,
        user: String? = nil,
        environment: String? = nil,
        fingerprint: String? = nil,
        version: String? = nil,
        checksum: String? = nil,
        entitlements: [String]? = nil
    ) {
        self.product = product
        self.policy = policy
        self.user = user
        self.environment = environment
        self.fingerprint = fingerprint
        self.version = version
        self.checksum = checksum
        self.entitlements = entitlements
    }

    /// Whether every field is unset.
    ///
    /// Note this still counts `version` and `checksum`, which are no longer
    /// sent: a scope carrying only those two is not "empty" but does render to
    /// an empty object, and `ValidateOptions` omits the `scope` key on that
    /// basis rather than on this one.
    public var isEmpty: Bool {
        product == nil && policy == nil && user == nil && environment == nil
            && fingerprint == nil && version == nil && checksum == nil
            && (entitlements?.isEmpty ?? true)
    }

    /// Renders this scope as the request-body object, omitting unset fields.
    ///
    /// `version` and `checksum` are omitted even when set: sending either makes
    /// the server reject the whole validate call with
    /// `422 SCOPE_NOT_SUPPORTED`, and a caller that set one is far better served
    /// by the remaining constraints being evaluated than by no verdict at all.
    var requestValue: JSONValue {
        var object: [String: JSONValue] = [:]
        if let product { object["product"] = .string(product) }
        if let policy { object["policy"] = .string(policy) }
        if let user { object["user"] = .string(user) }
        if let environment { object["environment"] = .string(environment) }
        if let fingerprint { object["fingerprint"] = .string(fingerprint) }
        if let entitlements, !entitlements.isEmpty {
            object["entitlements"] = .array(entitlements.map { .string($0) })
        }
        return .object(object)
    }
}
