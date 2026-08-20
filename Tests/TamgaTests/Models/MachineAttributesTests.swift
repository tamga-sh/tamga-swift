import Foundation
import Testing

@testable import Tamga

@Suite("MachineAttributes")
struct MachineAttributesTests {
    /// Regression: `MachineAttributes` used to declare explicit snake_case
    /// `CodingKeys` while the shared decoder also applies
    /// `.convertFromSnakeCase`. The two cancelled -- the strategy rewrote the
    /// wire key `heartbeat_status` to `heartbeatStatus`, lookup compared that
    /// against a CodingKey whose stringValue was `heartbeat_status`, matched
    /// nothing, and decoded nil. Every machine came back `.notStarted` with
    /// null timestamps regardless of what the server actually sent, which
    /// would silently defeat the dead-machine detection a heartbeat scheduler
    /// exists to provide.
    @Test("snake_case attributes decode off the wire")
    func snakeCaseAttributesDecode() throws {
        let json = """
        {"data":{"id":"m-1","type":"machines","attributes":{"fingerprint":"fp",\
        "heartbeat_status":"ALIVE","last_heartbeat_at":"2026-08-20T10:00:00Z"}}}
        """
        let payload = try TamgaJSONCoding.decoder.decode(
            JSONAPIPayload<MachineAttributes>.self, from: Data(json.utf8))
        let machine = Machine.fromResource(payload.data)
        #expect(machine.heartbeatStatus == .alive)
        #expect(machine.lastHeartbeatAt != nil)
    }

    @Test("an unrecognized heartbeat status decodes leniently")
    func unrecognizedHeartbeatStatusDecodesLeniently() throws {
        let json = """
        {"data":{"id":"m-1","type":"machines","attributes":{"heartbeat_status":"INVENTED"}}}
        """
        let payload = try TamgaJSONCoding.decoder.decode(
            JSONAPIPayload<MachineAttributes>.self, from: Data(json.utf8))

        #expect(Machine.fromResource(payload.data).heartbeatStatus == .notStarted)
    }
}
