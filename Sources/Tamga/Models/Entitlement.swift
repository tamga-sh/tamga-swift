import Foundation

/// Whether an entitlement is a boolean grant or a named, per-license counter.
///
/// Required and always present on every entitlement response -- unlike
/// `inherited`/`maxValue`/`currentValue` below, this is never omitted, so it
/// is modeled as a non-optional field on `Entitlement` itself. Mirrors
/// `ValidationCode`'s forward-compatible decoding style rather than a plain
/// `RawRepresentable` enum: an unrecognized wire value decodes to `.unknown`
/// instead of failing the whole response, so a server-side addition (a third
/// kind, say) can never break a released SDK.
public enum EntitlementKind: Equatable, Sendable {
    /// A boolean grant -- the only kind that existed before entitlement
    /// metering. `maxValue`/`currentValue` are present but not enforced for a
    /// flag.
    case flag
    /// A named, per-license counter with an independent cap. See
    /// `Entitlement.maxValue`/`Entitlement.currentValue`, and
    /// `TamgaClient.incrementEntitlementUsage`/`decrementEntitlementUsage`/
    /// `resetEntitlementUsage`.
    case meter
    /// A kind this SDK release does not recognize, carrying the raw wire value.
    case unknown(String)

    /// Every case with a fixed wire value, in the server's own order.
    static let knownValues: [(EntitlementKind, String)] = [
        (.flag, "flag"),
        (.meter, "meter")
    ]

    /// Maps a raw wire string, falling back to `.unknown` for anything
    /// unrecognized -- including a missing value, which decodes to
    /// `.unknown("")` rather than crashing a lenient response decode.
    public init(wireValue: String?) {
        guard let wireValue else {
            self = .unknown("")
            return
        }
        self = Self.knownValues.first { $0.1 == wireValue }?.0 ?? .unknown(wireValue)
    }

    /// This kind's wire string.
    public var wireValue: String {
        if case .unknown(let raw) = self {
            return raw
        }
        return Self.knownValues.first { $0.0 == self }?.1 ?? ""
    }
}

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
    /// Whether this is a boolean grant or a named, per-license counter.
    /// Always present; see `EntitlementKind`.
    public let kind: EntitlementKind
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
    /// is refused (`422 ENTITLEMENT_ALREADY_INHERITED`) for a `kind: .flag`
    /// entitlement -- a `kind: .meter` one may be attached directly even while
    /// also inherited, because direct attachment is what creates the
    /// per-license counter row -- and `TamgaClient.getEntitlement` returns
    /// `404` for it because the item route resolves direct attachments only.
    public let inherited: Bool?
    /// The effective cap on this entitlement's counter: the license's own
    /// override if it has one, else the policy's default, else `nil` for
    /// unlimited. Meaningless, though present, for `kind: .flag`.
    ///
    /// Emitted only by the license-scoped listing, like `inherited`.
    public let maxValue: Int?
    /// The running count, `0` if never incremented. `0` does not necessarily
    /// mean "never used" -- it also means "this entitlement is only inherited
    /// from the license's policy and has never been directly attached to this
    /// license", since only a direct attachment carries a counter row at all.
    /// Check `inherited` to tell the two apart.
    ///
    /// Emitted only by the license-scoped listing, like `inherited`.
    public let currentValue: Int?

    static func fromResource(_ resource: JSONAPIResource<EntitlementAttributes>) -> Entitlement {
        let attrs = resource.attributes
        return Entitlement(
            id: resource.id,
            name: attrs?.name,
            code: attrs?.code,
            kind: EntitlementKind(wireValue: attrs?.kind),
            created: attrs?.created,
            updated: attrs?.updated,
            metadata: attrs?.metadata,
            inherited: attrs?.inherited,
            maxValue: attrs?.maxValue,
            currentValue: attrs?.currentValue
        )
    }
}

/// The JSON:API `attributes` bag for an entitlement resource.
struct EntitlementAttributes: Decodable {
    let name: String?
    let code: String?
    /// `"flag"` or `"meter"`. Always present server-side, but kept optional
    /// here -- like every other field in this bag -- so a response missing it
    /// degrades to `EntitlementKind.unknown("")` rather than failing the
    /// whole decode.
    let kind: String?
    let created: Date?
    let updated: Date?
    let metadata: [String: JSONValue]?
    /// Emitted only by the license-scoped listing; absent elsewhere.
    let inherited: Bool?
    /// Emitted only by the license-scoped listing; absent elsewhere.
    let maxValue: Int?
    /// Emitted only by the license-scoped listing; absent elsewhere.
    let currentValue: Int?
}
