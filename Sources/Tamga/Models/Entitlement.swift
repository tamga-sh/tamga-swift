import Foundation

/// An entitlement resource.
///
/// Despite being nested under `/licenses/{id}/entitlements`, list and get
/// return full entitlement resources, not lightweight junction records.
///
/// `code` is the stable, developer-facing identifier and is what
/// `TamgaClient.hasEntitlement` matches on. `name` is a display label that may
/// collide or change independently -- never match on it.
public struct Entitlement: Equatable, Sendable {
    /// The entitlement's unique id.
    public let id: String
    /// The display label. Never match on this -- match on `code`.
    public let name: String?
    /// The stable, developer-facing entitlement code.
    public let code: String?
    /// When the entitlement was created.
    public let created: Date?
    /// When the entitlement was last updated.
    public let updated: Date?
    /// Arbitrary key/value metadata.
    public let metadata: [String: JSONValue]?
    /// `true` when the license holds this through its policy rather than by a
    /// direct attachment, `nil` when the response does not say.
    ///
    /// Only the license-scoped list emits this flag; account-, policy- and
    /// release-scoped entitlement responses omit it, hence the optional.
    ///
    /// It gates more than presentation. An inherited entitlement cannot be
    /// detached from the license (`403 POLICY_ENTITLEMENT`), attaching it again
    /// is refused (`422 ENTITLEMENT_ALREADY_INHERITED`), and
    /// `TamgaClient.getEntitlement` returns `404` for it because the item route
    /// resolves direct attachments only.
    public let inherited: Bool?

    static func fromResource(_ resource: JSONAPIResource<EntitlementAttributes>) -> Entitlement {
        let attrs = resource.attributes
        return Entitlement(
            id: resource.id,
            name: attrs?.name,
            code: attrs?.code,
            created: attrs?.created,
            updated: attrs?.updated,
            metadata: attrs?.metadata,
            inherited: attrs?.inherited
        )
    }
}

/// The JSON:API `attributes` bag for an entitlement resource.
struct EntitlementAttributes: Decodable {
    let name: String?
    let code: String?
    let created: Date?
    let updated: Date?
    let metadata: [String: JSONValue]?
    /// Emitted only by the license-scoped listing; absent elsewhere.
    let inherited: Bool?
}
