import Foundation

/// A published release, as returned by the auto-update check.
///
/// **This resource's attributes are camelCase on the wire**, unlike `machines`,
/// `licenses`, `policies`, `components`, `processes` and `entitlements`, which
/// are all snake_case. The server declares `#[serde(rename_all = "camelCase")]`
/// on this attribute bag alone, so `product_id` goes over as `productId`. The
/// shared decoder's snake-case conversion leaves a key with no underscores in
/// it untouched, so both spellings land on the same Swift property name and no
/// per-type decoder is needed -- but do not generalize "the API is snake_case"
/// from the other resources.
public struct Release: Equatable, Sendable {
    /// The release's unique id.
    public let id: String
    /// The owning product's id. Wire name `productId`.
    public let productId: String?
    /// Display name, when the product set one.
    public let name: String?
    /// The version string exactly as the product publishes it.
    ///
    /// Deliberately not parsed or compared client-side. The server decides what
    /// "newer" means, including how an optional `constraint` narrows it, and a
    /// second opinion computed here could only ever disagree with it.
    public let version: String?
    /// The release channel, e.g. `"stable"` or `"beta"`.
    public let channel: String?
    /// Publication status.
    public let status: String?
    /// An optional tag. **Absent rather than null** when unset -- the server
    /// skips the key entirely.
    public let tag: String?
    /// Arbitrary product-set metadata.
    public let metadata: [String: JSONValue]?
    /// When the release was created.
    public let created: Date?
    /// When the release was last updated.
    public let updated: Date?

    static func fromResource(_ resource: JSONAPIResource<ReleaseAttributes>) -> Release {
        let attrs = resource.attributes
        return Release(
            id: resource.id,
            productId: attrs?.productId,
            name: attrs?.name,
            version: attrs?.version,
            channel: attrs?.channel,
            status: attrs?.status,
            tag: attrs?.tag,
            metadata: attrs?.metadata,
            created: attrs?.created,
            updated: attrs?.updated
        )
    }
}

/// The JSON:API `attributes` bag for a release resource. See `Release` for the
/// camelCase note.
struct ReleaseAttributes: Decodable {
    let productId: String?
    let name: String?
    let version: String?
    let channel: String?
    let status: String?
    let tag: String?
    let metadata: [String: JSONValue]?
    let created: Date?
    let updated: Date?
}

/// The query an auto-update check sends.
///
/// Four fields are required by the server; a missing one is rejected before the
/// handler runs, and that rejection is **not** a JSON:API error document but a
/// plain-text `400`, so it surfaces as `TamgaError.api` with
/// `code == TamgaError.APIError.unknownCode` and `httpStatus == 400`.
public struct UpgradeCheckOptions: Equatable, Sendable {
    /// The product's **UUID**, not its code. Required.
    ///
    /// The server parses this as a UUID before anything else, so a product code
    /// here is a `400`, and an id for a product that does not exist is a `404`
    /// `NOT_FOUND` -- neither of which means "no update".
    public var productId: String
    /// The platform to look for, e.g. `"darwin"`. Required.
    public var platform: String
    /// The artifact filetype to look for, e.g. `"dmg"`. Required.
    public var filetype: String
    /// The version currently installed. Required, and must parse as semver --
    /// otherwise the server answers `422 INVALID_VERSION`.
    public var version: String
    /// Restricts the search to one channel.
    ///
    /// **Omitting it does not mean "stable".** With no channel the server
    /// matches *every* channel, `alpha` and `dev` included, so an updater that
    /// leaves this unset can offer a prerelease build to a production install.
    public var channel: String?
    /// A semver requirement narrowing what counts as an upgrade, e.g. `"^2"`.
    ///
    /// Omitting it is **not** "any newer version": the server defaults to a
    /// pessimistic `~major.minor.patch`, i.e. patch-level upgrades only. Ask for
    /// `"^1"` or similar to see minor bumps. A requirement the server cannot
    /// parse is `422 INVALID_CONSTRAINT`.
    public var constraint: String?

    /// Creates an upgrade query.
    public init(
        productId: String,
        platform: String,
        filetype: String,
        version: String,
        channel: String? = nil,
        constraint: String? = nil
    ) {
        self.productId = productId
        self.platform = platform
        self.filetype = filetype
        self.version = version
        self.channel = channel
        self.constraint = constraint
    }

    /// The four required parameters plus whichever optional ones are set. Flat
    /// names, not the bracketed `filter[...]`/`page[...]` spelling the list
    /// routes use.
    var queryItems: [URLQueryItem] {
        var items = [
            URLQueryItem(name: "product", value: productId),
            URLQueryItem(name: "platform", value: platform),
            URLQueryItem(name: "filetype", value: filetype),
            URLQueryItem(name: "version", value: version)
        ]
        if let channel {
            items.append(URLQueryItem(name: "channel", value: channel))
        }
        if let constraint {
            items.append(URLQueryItem(name: "constraint", value: constraint))
        }
        return items
    }
}
