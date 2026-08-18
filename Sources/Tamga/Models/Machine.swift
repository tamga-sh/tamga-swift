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
/// **Scope note**: models exactly the fields needed to decode a checked-out
/// `.machine` file's embedded resource (`Checkout/MachineFile.swift`) --
/// the full `TamgaClient`-facing machine-management surface (create/update/
/// heartbeat-ping endpoints, `HeartbeatScheduler`) is still deferred to a
/// future release.
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

    // No explicit init: Swift synthesizes an equivalent memberwise one
    // automatically (internal visibility, matching the properties above).

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
            metadata: attrs?.metadata
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

    enum CodingKeys: String, CodingKey {
        case fingerprint, name, platform
        case heartbeatStatus = "heartbeat_status"
        case lastHeartbeatAt = "last_heartbeat_at"
        case lastCheckOutAt = "last_check_out_at"
        case metadata
    }
}
