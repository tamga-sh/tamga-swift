import Foundation

/// A license resource, flattened from the JSON:API `data.id` + `data.attributes`
/// shape for ergonomic use -- mirrors tamga-dotnet's `License` flattening
/// pattern.
///
/// The same type serves two paths: the subset embedded in a checked-out `.lic`
/// file (`Checkout/LicenseFile.swift`) and the full resource returned by the
/// validation and check-in endpoints. A field the current path does not carry
/// is simply `nil` or zero -- an offline file, for instance, carries no
/// `status` or `machinesCount`.
///
/// Relationship ids (product/policy/user/environment) are not modeled: this
/// resource carries no `relationships` object server-side.
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
    /// The license's display name.
    public let name: String?
    /// The license status string. Absent when decoded from an offline file.
    public let status: String?
    /// The key/checkout signing scheme, as a raw wire string.
    public let scheme: String?
    /// The machine limit carried on the license.
    public let maxMachines: Int?
    /// The user limit carried on the license.
    public let maxUsers: Int?
    /// The use limit carried on the license.
    public let maxUses: Int?
    /// How many machines are currently registered against this license.
    public let machinesCount: Int
    /// When the license was last checked out.
    public let lastCheckOutAt: Date?
    /// When the license was created.
    public let created: Date?
    /// When the license was last updated.
    public let updated: Date?
    /// Whether the license is protected.
    public let isProtected: Bool
    /// Whether the license is floating.
    public let floating: Bool
    /// Whether the license is strict.
    public let strict: Bool
    /// Whether checkout files for this license are encrypted.
    public let encrypted: Bool

    /// The API-facing fields default so the offline decode path, which carries
    /// none of them, can keep constructing a `License` unchanged.
    init(
        id: String,
        key: String?,
        suspended: Bool,
        expiry: Date?,
        uses: Int,
        lastValidatedAt: Date?,
        lastCheckInAt: Date?,
        metadata: [String: JSONValue]?,
        name: String? = nil,
        status: String? = nil,
        scheme: String? = nil,
        maxMachines: Int? = nil,
        maxUsers: Int? = nil,
        maxUses: Int? = nil,
        machinesCount: Int = 0,
        lastCheckOutAt: Date? = nil,
        created: Date? = nil,
        updated: Date? = nil,
        isProtected: Bool = false,
        floating: Bool = false,
        strict: Bool = false,
        encrypted: Bool = false
    ) {
        self.id = id
        self.key = key
        self.suspended = suspended
        self.expiry = expiry
        self.uses = uses
        self.lastValidatedAt = lastValidatedAt
        self.lastCheckInAt = lastCheckInAt
        self.metadata = metadata
        self.name = name
        self.status = status
        self.scheme = scheme
        self.maxMachines = maxMachines
        self.maxUsers = maxUsers
        self.maxUses = maxUses
        self.machinesCount = machinesCount
        self.lastCheckOutAt = lastCheckOutAt
        self.created = created
        self.updated = updated
        self.isProtected = isProtected
        self.floating = floating
        self.strict = strict
        self.encrypted = encrypted
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
            metadata: attrs?.metadata,
            name: attrs?.name,
            status: attrs?.status,
            scheme: attrs?.scheme,
            maxMachines: attrs?.maxMachines,
            maxUsers: attrs?.maxUsers,
            maxUses: attrs?.maxUses,
            machinesCount: attrs?.machinesCount ?? 0,
            lastCheckOutAt: attrs?.lastCheckOutAt,
            created: attrs?.created,
            updated: attrs?.updated,
            isProtected: attrs?.protected ?? false,
            floating: attrs?.floating ?? false,
            strict: attrs?.strict ?? false,
            encrypted: attrs?.encrypted ?? false
        )
    }
}

/// The JSON:API `attributes` bag for a license resource.
struct LicenseAttributes: Decodable {
    let key: String?
    // Optional, though the server always sends them today. A non-optional
    // scalar here makes one omitted field fail the whole response decode,
    // which is the opposite of the forward-compatibility stance the rest of
    // this SDK takes -- unknown fields are ignored, so missing ones should not
    // be fatal either.
    let suspended: Bool?
    let expiry: Date?
    let uses: Int?
    let lastValidatedAt: Date?
    let lastCheckInAt: Date?
    let metadata: [String: JSONValue]?
    let name: String?
    let status: String?
    let scheme: String?
    let maxMachines: Int?
    let maxUsers: Int?
    let maxUses: Int?
    let machinesCount: Int?
    let lastCheckOutAt: Date?
    let created: Date?
    let updated: Date?
    let protected: Bool?
    let floating: Bool?
    let strict: Bool?
    let encrypted: Bool?
}
