import Foundation

/// A process resource -- a running process registered against a machine.
///
/// Named `MachineProcess` rather than `Process` deliberately: `Foundation`
/// already exports a `Process` type (a subprocess launcher) on every platform,
/// and shadowing it would make `import Tamga` alongside `import Foundation`
/// ambiguous at every use site for no benefit. The sibling SDKs call this
/// `Process` because their standard libraries have no such clash.
///
/// **The process id is a `String` on the wire, not an integer.** The server
/// types it that way, and this SDK sends and accepts it as a string even
/// though operating-system process ids are numeric. A caller holding a numeric
/// pid must stringify it explicitly at the call site rather than have this SDK
/// coerce it silently.
///
/// Unlike `Machine` there is deliberately no heartbeat-status field. A
/// process's aliveness is purely a function of `lastHeartbeatAt` against the
/// hardcoded 30-second window: a dead process row is deleted outright rather
/// than tracked through a dead/resurrected state.
public struct MachineProcess: Equatable, Sendable {
    /// The process resource's unique id.
    public let id: String
    /// The operating-system process id, as a string.
    public let pid: String?
    /// The id of the machine this process belongs to.
    public let machineId: String?
    /// When this process last pinged.
    public let lastHeartbeatAt: Date?
    /// When the process was registered.
    public let created: Date?
    /// When the process was last updated.
    public let updated: Date?
    /// Arbitrary key/value metadata.
    public let metadata: [String: JSONValue]?

    static func fromResource(_ resource: JSONAPIResource<ProcessAttributes>) -> MachineProcess {
        let attrs = resource.attributes
        return MachineProcess(
            id: resource.id,
            pid: attrs?.pid,
            machineId: attrs?.machineId,
            lastHeartbeatAt: attrs?.lastHeartbeatAt,
            created: attrs?.created,
            updated: attrs?.updated,
            metadata: attrs?.metadata
        )
    }
}

/// The JSON:API `attributes` bag for a process resource.
struct ProcessAttributes: Decodable {
    let pid: String?
    let machineId: String?
    let lastHeartbeatAt: Date?
    let created: Date?
    let updated: Date?
    let metadata: [String: JSONValue]?
}
