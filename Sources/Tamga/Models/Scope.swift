import Foundation

/// Optional constraints sent as `meta.scope` on a validate-by-id request.
///
/// Every field is optional; an unset field means "no constraint, skip this
/// check" and is omitted from the request body entirely rather than sent as
/// null -- the server treats a present key as a constraint to evaluate.
///
/// **Only `product`, `policy`, `user` and `environment` are enforced
/// server-side.** The remaining four are parsed and then silently ignored.
/// They are modeled for forward-compatibility -- never document or surface
/// them as constraints that currently work.
public struct Scope: Equatable, Sendable {
    /// Enforced server-side.
    public var product: String?
    /// Enforced server-side.
    public var policy: String?
    /// Enforced server-side.
    public var user: String?
    /// Enforced server-side.
    public var environment: String?
    /// Sent and parsed, but **not enforced** server-side.
    public var fingerprint: String?
    /// Sent and parsed, but **not enforced** server-side.
    public var version: String?
    /// Sent and parsed, but **not enforced** server-side.
    public var checksum: String?
    /// Sent and parsed, but **not enforced** server-side.
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

    /// Whether every field is unset, in which case `scope` is omitted entirely.
    public var isEmpty: Bool {
        product == nil && policy == nil && user == nil && environment == nil
            && fingerprint == nil && version == nil && checksum == nil
            && (entitlements?.isEmpty ?? true)
    }

    /// Renders this scope as the request-body object, omitting unset fields.
    var requestValue: JSONValue {
        var object: [String: JSONValue] = [:]
        if let product { object["product"] = .string(product) }
        if let policy { object["policy"] = .string(policy) }
        if let user { object["user"] = .string(user) }
        if let environment { object["environment"] = .string(environment) }
        if let fingerprint { object["fingerprint"] = .string(fingerprint) }
        if let version { object["version"] = .string(version) }
        if let checksum { object["checksum"] = .string(checksum) }
        if let entitlements, !entitlements.isEmpty {
            object["entitlements"] = .array(entitlements.map { .string($0) })
        }
        return .object(object)
    }
}
