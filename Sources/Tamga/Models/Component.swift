import Foundation

/// A component resource -- a sub-part of a machine, identified by its own
/// fingerprint and unique per machine.
public struct Component: Equatable, Sendable {
    /// The component's unique id.
    public let id: String
    /// The component's fingerprint, unique within its machine.
    public let fingerprint: String?
    /// The component's display name.
    public let name: String?
    /// The id of the machine this component belongs to.
    public let machineId: String?
    /// When the component was created.
    public let created: Date?
    /// When the component was last updated.
    public let updated: Date?
    /// Arbitrary key/value metadata.
    public let metadata: [String: JSONValue]?

    static func fromResource(_ resource: JSONAPIResource<ComponentAttributes>) -> Component {
        let attrs = resource.attributes
        return Component(
            id: resource.id,
            fingerprint: attrs?.fingerprint,
            name: attrs?.name,
            machineId: attrs?.machineId,
            created: attrs?.created,
            updated: attrs?.updated,
            metadata: attrs?.metadata
        )
    }
}

/// The JSON:API `attributes` bag for a component resource.
struct ComponentAttributes: Decodable {
    let fingerprint: String?
    let name: String?
    let machineId: String?
    let created: Date?
    let updated: Date?
    let metadata: [String: JSONValue]?
}
