import Foundation

/// A machine's heartbeat state. GOTCHA: the 600s (10 min) heartbeat window is
/// hardcoded server-side, NOT driven by `policy.heartbeat_duration` -- a
/// future heartbeat-scheduler helper must not derive its ping interval from
/// that field.
public enum HeartbeatStatus: String, Equatable, Sendable {
    /// Wire value `NOT_STARTED` -- never pinged.
    case notStarted = "NOT_STARTED"
    /// Wire value `ALIVE` -- pinged within the window.
    case alive = "ALIVE"
    /// Wire value `DEAD` -- window elapsed with no ping.
    case dead = "DEAD"
    /// Wire value `RESURRECTED` -- a new ping arrived after a death event was
    /// already recorded, within the resurrection grace window.
    case resurrected = "RESURRECTED"

    init(wireValue: String?) {
        self = HeartbeatStatus(rawValue: wireValue ?? "") ?? .notStarted
    }
}

/// A machine resource, flattened from the JSON:API `data.id` + `data.attributes`
/// shape, mirroring `License`'s flattening pattern.
///
/// The same type serves two paths: the subset embedded in a checked-out
/// `.machine` file (`Checkout/MachineFile.swift`) and the full resource
/// returned by the machine endpoints. A field the current path does not carry
/// is simply `nil`.
public struct Machine: Equatable, Sendable {
    /// The machine's unique ID.
    public let id: String
    /// The machine's fingerprint identifier.
    public let fingerprint: String?
    /// The machine's display name.
    public let name: String?
    /// The machine's platform/OS identifier.
    public let platform: String?
    /// The machine's current heartbeat status.
    public let heartbeatStatus: HeartbeatStatus
    /// When the machine last sent a heartbeat ping.
    public let lastHeartbeatAt: Date?
    /// When the machine was last checked out (offline `.machine` file issued).
    public let lastCheckOutAt: Date?
    /// Arbitrary caller-supplied metadata attached to the machine.
    public let metadata: [String: JSONValue]?
    /// The machine's reported IP address.
    public let ip: String?
    /// The machine's hostname.
    public let hostname: String?
    /// The machine's reported core count.
    public let cores: Int?
    /// The machine's reported memory in bytes.
    public let memory: Int64?
    /// The machine's reported disk in bytes.
    public let disk: Int64?
    /// When the next heartbeat is expected.
    public let nextHeartbeatAt: Date?
    /// When the machine was registered.
    public let created: Date?
    /// When the machine was last updated.
    public let updated: Date?

    /// The API-facing fields default so the offline decode path, which carries
    /// none of them, can keep constructing a `Machine` unchanged.
    init(
        id: String,
        fingerprint: String?,
        name: String?,
        platform: String?,
        heartbeatStatus: HeartbeatStatus,
        lastHeartbeatAt: Date?,
        lastCheckOutAt: Date?,
        metadata: [String: JSONValue]?,
        ip: String? = nil,
        hostname: String? = nil,
        cores: Int? = nil,
        memory: Int64? = nil,
        disk: Int64? = nil,
        nextHeartbeatAt: Date? = nil,
        created: Date? = nil,
        updated: Date? = nil
    ) {
        self.id = id
        self.fingerprint = fingerprint
        self.name = name
        self.platform = platform
        self.heartbeatStatus = heartbeatStatus
        self.lastHeartbeatAt = lastHeartbeatAt
        self.lastCheckOutAt = lastCheckOutAt
        self.metadata = metadata
        self.ip = ip
        self.hostname = hostname
        self.cores = cores
        self.memory = memory
        self.disk = disk
        self.nextHeartbeatAt = nextHeartbeatAt
        self.created = created
        self.updated = updated
    }

    /// Flattens a raw JSON:API machine resource into a `Machine`. Shared by
    /// `TamgaClient`'s (future) response mapping and `Checkout.MachineFile`'s
    /// embedded-payload parsing.
    static func fromResource(_ resource: JSONAPIResource<MachineAttributes>) -> Machine {
        let attrs = resource.attributes
        return Machine(
            id: resource.id,
            fingerprint: attrs?.fingerprint,
            name: attrs?.name,
            platform: attrs?.platform,
            heartbeatStatus: HeartbeatStatus(wireValue: attrs?.heartbeatStatus),
            lastHeartbeatAt: attrs?.lastHeartbeatAt,
            lastCheckOutAt: attrs?.lastCheckOutAt,
            metadata: attrs?.metadata,
            ip: attrs?.ip,
            hostname: attrs?.hostname,
            cores: attrs?.cores,
            memory: attrs?.memory,
            disk: attrs?.disk,
            nextHeartbeatAt: attrs?.nextHeartbeatAt,
            created: attrs?.created,
            updated: attrs?.updated
        )
    }
}

/// The JSON:API `attributes` bag for a machine resource.
struct MachineAttributes: Decodable {
    let fingerprint: String?
    let name: String?
    let platform: String?
    /// Decoded as a raw string, not `HeartbeatStatus` directly -- `HeartbeatStatus`'s
    /// lenient `init(wireValue:)` fallback (unrecognized -> `.notStarted`) only
    /// applies if decoding doesn't already fail on an unrecognized rawValue
    /// first, which a direct `HeartbeatStatus: Decodable` conformance via
    /// `RawRepresentable` would do.
    let heartbeatStatus: String?
    let lastHeartbeatAt: Date?
    let lastCheckOutAt: Date?
    let metadata: [String: JSONValue]?
    let ip: String?
    let hostname: String?
    let cores: Int?
    let memory: Int64?
    let disk: Int64?
    let nextHeartbeatAt: Date?
    let created: Date?
    let updated: Date?

    // No explicit CodingKeys. This type used to declare snake_case ones, which
    // silently cancelled against the shared decoder's `.convertFromSnakeCase`
    // strategy: the strategy rewrote the wire key `heartbeat_status` to
    // `heartbeatStatus`, then lookup compared that against a CodingKey whose
    // stringValue was `heartbeat_status`, matched nothing, and decoded nil.
    // Every machine came back with `.notStarted` and null timestamps no matter
    // what the server sent. `LicenseAttributes` never had the redundant keys
    // and was always correct.
}
