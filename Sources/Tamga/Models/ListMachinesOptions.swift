import Foundation

/// The columns `listMachines` may be sorted by.
///
/// Constants rather than a Swift enum, matching `ExpirationStrategy` and
/// `AuthenticationStrategy` in this SDK: the server rejects an unknown column
/// with a `400`, and a closed enum would have to grow a case -- a breaking
/// change -- the day a fifth column becomes sortable.
public enum MachineSortField {
    /// Registration time. The server's own default.
    public static let created = "created_at"
    /// Last modification time.
    public static let updated = "updated_at"
    /// Display name.
    public static let name = "name"
    /// Last heartbeat ping.
    public static let lastHeartbeatAt = "last_heartbeat_at"

    /// Every column the server accepts. Anything else is a `400`, not a
    /// silent fallback to the default.
    public static let allValues = [created, updated, name, lastHeartbeatAt]
}

/// Request options for `listMachines`.
///
/// **This route is offset-paginated, and it is the only one in this SDK that
/// is.** Components, processes and entitlements are keyset (or, for
/// entitlements, not paginable at all). Ask for a page by number and read
/// `OffsetPage.pageInfo` to find out whether another exists.
public struct ListMachinesOptions: Equatable, Sendable {
    /// The 1-based page to fetch. Values below 1 are not sent, leaving the
    /// server's own default of page 1.
    public var pageNumber: Int
    /// How many machines per page. Clamped to `TamgaClient.defaultPageSize`,
    /// the server's maximum; a non-positive value requests that maximum.
    public var pageSize: Int
    /// Restrict to machines registered against these license ids.
    public var licenseIds: [String]
    /// Restrict to machines owned by these user ids.
    public var ownerIds: [String]
    /// Restrict to machines in these group ids.
    public var groupIds: [String]
    /// Restrict to these exact platform strings.
    public var platforms: [String]
    /// Free-text search.
    ///
    /// **A substring match, not an equality filter, and it spans three
    /// columns.** The server ORs `name`, `hostname` and `fingerprint` together
    /// with `ILIKE '%term%'`, so a fingerprint passed here reliably returns the
    /// machine carrying it -- along with any machine whose name or hostname
    /// merely contains the same text. Compare `Machine.fingerprint` yourself
    /// before treating a hit as the machine you meant.
    public var query: String?
    /// The column to sort by -- one of `MachineSortField.allValues`. An
    /// unrecognized value is a `400`, not a fallback.
    public var sort: String?
    /// Sort descending rather than ascending.
    public var descending: Bool

    /// Creates list options.
    public init(
        pageNumber: Int = 0,
        pageSize: Int = 0,
        licenseIds: [String] = [],
        ownerIds: [String] = [],
        groupIds: [String] = [],
        platforms: [String] = [],
        query: String? = nil,
        sort: String? = nil,
        descending: Bool = false
    ) {
        self.pageNumber = pageNumber
        self.pageSize = pageSize
        self.licenseIds = licenseIds
        self.ownerIds = ownerIds
        self.groupIds = groupIds
        self.platforms = platforms
        self.query = query
        self.sort = sort
        self.descending = descending
    }

    /// The query string this renders to.
    ///
    /// Multi-value filters are **comma-separated inside one value**, never
    /// repeated keys: the server parses each key as a single string, so
    /// `filter[license]=A&filter[license]=B` silently collapses to `B` and
    /// quietly drops half the filter.
    var queryItems: [URLQueryItem] {
        var items = [
            URLQueryItem(name: "page[size]",
                         value: String(TamgaClient.effectiveLimit(ListOptions(limit: pageSize))))
        ]
        if pageNumber > 0 {
            items.append(URLQueryItem(name: "page[number]", value: String(pageNumber)))
        }
        appendCsv(&items, name: "filter[license]", values: licenseIds)
        appendCsv(&items, name: "filter[owner]", values: ownerIds)
        appendCsv(&items, name: "filter[group]", values: groupIds)
        appendCsv(&items, name: "filter[platform]", values: platforms)
        if let query, !query.isEmpty {
            items.append(URLQueryItem(name: "filter[q]", value: query))
        }
        if let sort, !sort.isEmpty {
            items.append(URLQueryItem(name: "sort", value: sort))
            items.append(URLQueryItem(name: "order", value: descending ? "desc" : "asc"))
        }
        return items
    }

    private func appendCsv(_ items: inout [URLQueryItem], name: String, values: [String]) {
        guard !values.isEmpty else { return }
        items.append(URLQueryItem(name: name, value: values.joined(separator: ",")))
    }
}

/// Fields `updateMachine` may change.
///
/// **Omitting a field leaves the column alone; it does not clear it.** The
/// server merges with `COALESCE`, so there is no way to null out `name`, `ip`,
/// `hostname`, `platform` or `metadata` through this endpoint -- sending an
/// explicit null is indistinguishable from omitting the key.
///
/// `fingerprint` and the license/owner/group relationships are not updatable
/// here. Owner and group have their own routes, which this SDK does not wrap.
public struct UpdateMachineOptions: Equatable, Sendable {
    /// New display name.
    public var name: String?
    /// New reported IP address.
    public var ip: String?
    /// New reported hostname.
    public var hostname: String?
    /// New reported platform identifier.
    public var platform: String?
    /// New reported core count.
    public var cores: Int?
    /// New reported memory, in **megabytes**. Not bytes -- see
    /// `CreateMachineOptions.memory`.
    public var memory: Int64?
    /// New reported disk, in **megabytes**. Not bytes.
    public var disk: Int64?
    /// Replacement metadata. Replaces the whole object rather than merging into
    /// it.
    public var metadata: [String: JSONValue]?

    /// Creates update options. Every field defaults to "leave unchanged".
    public init(
        name: String? = nil,
        ip: String? = nil,
        hostname: String? = nil,
        platform: String? = nil,
        cores: Int? = nil,
        memory: Int64? = nil,
        disk: Int64? = nil,
        metadata: [String: JSONValue]? = nil
    ) {
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.platform = platform
        self.cores = cores
        self.memory = memory
        self.disk = disk
        self.metadata = metadata
    }

    /// Whether this would change anything at all.
    var isEmpty: Bool {
        name == nil && ip == nil && hostname == nil && platform == nil
            && cores == nil && memory == nil && disk == nil && metadata == nil
    }

    /// The JSON:API request body.
    ///
    /// Enveloped, like `createMachine` and unlike the flat component and
    /// process creates. `data.type` is a non-optional field on the server's
    /// request struct, so omitting it fails deserialization before the handler
    /// runs -- even though the value is never read once parsed (the field
    /// carries `#[allow(dead_code)]`). Send it; do not rely on its content
    /// meaning anything.
    ///
    /// Unset fields are omitted rather than sent as null, which is what
    /// "leave unchanged" looks like on the wire. Both spellings mean the same
    /// thing to the server; omitting is the honest one.
    var requestBody: JSONValue {
        var attributes: [String: JSONValue] = [:]
        if let name { attributes["name"] = .string(name) }
        if let ip { attributes["ip"] = .string(ip) }
        if let hostname { attributes["hostname"] = .string(hostname) }
        if let platform { attributes["platform"] = .string(platform) }
        if let cores { attributes["cores"] = .int(Int64(cores)) }
        if let memory { attributes["memory"] = .int(memory) }
        if let disk { attributes["disk"] = .int(disk) }
        if let metadata { attributes["metadata"] = .object(metadata) }
        return .object([
            "data": .object([
                "type": .string("machines"),
                "attributes": .object(attributes)
            ])
        ])
    }
}
