import Foundation
import Testing

@testable import Tamga

/// Fixtures for the endpoints added alongside the read surface.
enum SurfaceFixtures {
    static let health = #"{"status":"ok","version":"1.8.3","uptime_secs":4210}"#

    /// Note the camelCase `productId` -- releases are the one resource whose
    /// attribute bag is camelCase server-side.
    static let release = """
    {"data":{"id":"rel-1","type":"releases","attributes":{\
    "productId":"prod-9","name":"Acme 2.0","version":"2.0.0","channel":"stable",\
    "status":"PUBLISHED","tag":"ga","metadata":{},\
    "created":"2026-08-01T00:00:00Z","updated":"2026-08-02T00:00:00Z"}}}
    """

    static let policy = """
    {"data":{"id":"pol-1","type":"policies","attributes":{"name":"Standard",\
    "heartbeat_duration":90,"require_heartbeat":true,"overage_strategy":"DENY_ACCESS",\
    "check_in_interval":"day"}}}
    """

    static func machine(id: String = "mach-1", fingerprint: String = "fp-1",
                        status: String = "ALIVE") -> String {
        """
        {"data":{"id":"\(id)","type":"machines","attributes":{"fingerprint":"\(fingerprint)",\
        "heartbeat_status":"\(status)","next_heartbeat_at":"2026-08-20T10:10:00Z"}}}
        """
    }

    static func machineList(_ fingerprints: [String], total: Int? = nil,
                            withMeta: Bool = true) -> String {
        let items = fingerprints.enumerated().map { index, fingerprint in
            """
            {"id":"mach-\(index)","type":"machines",\
            "attributes":{"fingerprint":"\(fingerprint)","heartbeat_status":"DEAD"}}
            """
        }.joined(separator: ",")
        let meta = withMeta
            ? #","meta":{"page":{"number":1,"size":100,"total":\#(total ?? fingerprints.count),"totalPages":1}}"#
            : ""
        return "{\"data\":[\(items)]\(meta)}"
    }

    static func processList(_ count: Int) -> String {
        let items = (0..<count).map { index in
            """
            {"id":"proc-\(index)","type":"processes",\
            "attributes":{"pid":"\(1000 + index)","machine_id":"mach-1"}}
            """
        }.joined(separator: ",")
        return "{\"data\":[\(items)]}"
    }

    static func conflict(code: String = "FINGERPRINT_TAKEN") -> String {
        """
        {"errors":[{"id":"e-1","status":"409","code":"\(code)","title":"Conflict",\
        "detail":"This fingerprint is already activated"}]}
        """
    }
}

/// Sequential `async` map, so a test can read back a recorded request list from
/// an actor without introducing concurrency it is not testing.
extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var results: [T] = []
        for element in self {
            results.append(try await transform(element))
        }
        return results
    }
}
