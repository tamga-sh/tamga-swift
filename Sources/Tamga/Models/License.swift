import Foundation

/// A license resource, flattened from the JSON:API `data.id` + `data.attributes`
/// shape for ergonomic use -- mirrors tamga-dotnet's `License` flattening
/// pattern.
///
/// **Scope note**: this models exactly the fields needed to decode a
/// checked-out `.lic` file's embedded resource (`Checkout/LicenseFile.swift`)
/// -- entitlement caching (`hasEntitlement(code:)`), relationship IDs
/// (product/policy/user/environment), and the full `TamgaClient`-facing
/// validate-by-key/validate-by-ID response shapes are still deferred to a
/// future session per `docs/plans/tamga-swift.plan.md` Sections D and K, same
/// as before this file had any real implementation.
public struct License: Equatable, Sendable {
    /// The license's unique identifier.
    public let id: String
    /// The license key string.
    public let key: String?
    /// Whether the license has been manually suspended.
    public let suspended: Bool
    /// The license's expiration timestamp, if any.
    public let expiry: Date?
    /// The number of times the license has been used.
    public let uses: Int
    /// Timestamp of the license's last successful validation, if any.
    public let lastValidatedAt: Date?
    /// Timestamp of the license's last check-in, if any.
    public let lastCheckInAt: Date?
    /// Arbitrary key/value metadata attached to the license.
    public let metadata: [String: JSONValue]?

    init(id: String, key: String?, suspended: Bool, expiry: Date?, uses: Int, lastValidatedAt: Date?, lastCheckInAt: Date?, metadata: [String: JSONValue]?) {
        self.id = id
        self.key = key
        self.suspended = suspended
        self.expiry = expiry
        self.uses = uses
        self.lastValidatedAt = lastValidatedAt
        self.lastCheckInAt = lastCheckInAt
        self.metadata = metadata
    }

    /// Flattens a raw JSON:API license resource into a `License`. Shared by
    /// `TamgaClient`'s (future) response mapping and `Checkout.LicenseFile`'s
    /// embedded-payload parsing, so both paths produce an identically-shaped
    /// result.
    static func fromResource(_ resource: JSONAPIResource<LicenseAttributes>) -> License {
        let attrs = resource.attributes
        return License(
            id: resource.id,
            key: attrs?.key,
            suspended: attrs?.suspended ?? false,
            expiry: attrs?.expiry,
            uses: attrs?.uses ?? 0,
            lastValidatedAt: attrs?.lastValidatedAt,
            lastCheckInAt: attrs?.lastCheckInAt,
            metadata: attrs?.metadata
        )
    }
}

/// The JSON:API `attributes` bag for a license resource.
struct LicenseAttributes: Decodable {
    let key: String?
    let suspended: Bool
    let expiry: Date?
    let uses: Int
    let lastValidatedAt: Date?
    let lastCheckInAt: Date?
    let metadata: [String: JSONValue]?
}
