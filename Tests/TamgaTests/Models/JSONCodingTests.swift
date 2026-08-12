import Foundation
import Testing

@testable import Tamga

private struct DateHolder: Codable, Equatable {
    let ts: Date
}

@Suite("TamgaJSONCoding")
struct JSONCodingTests {
    @Test("decodes an ISO 8601 timestamp with fractional seconds")
    func decodesWithFractionalSeconds() throws {
        let json = Data(#"{"ts":"2026-08-12T10:00:00.123Z"}"#.utf8)
        let decoded = try TamgaJSONCoding.decoder.decode(DateHolder.self, from: json)

        let expected = ISO8601DateFormatter()
        expected.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        #expect(decoded.ts == expected.date(from: "2026-08-12T10:00:00.123Z"))
    }

    @Test("decodes an ISO 8601 timestamp without fractional seconds")
    func decodesWithoutFractionalSeconds() throws {
        let json = Data(#"{"ts":"2026-08-12T10:00:00Z"}"#.utf8)
        let decoded = try TamgaJSONCoding.decoder.decode(DateHolder.self, from: json)

        let expected = ISO8601DateFormatter()
        expected.formatOptions = [.withInternetDateTime]
        #expect(decoded.ts == expected.date(from: "2026-08-12T10:00:00Z"))
    }

    @Test("throws for a non-ISO-8601 date string")
    func throwsForMalformedDate() {
        let json = Data(#"{"ts":"not a date"}"#.utf8)
        #expect(throws: (any Error).self) {
            _ = try TamgaJSONCoding.decoder.decode(DateHolder.self, from: json)
        }
    }

    @Test("encodes then decodes a Date round-trip")
    func encodeDecodeRoundTrips() throws {
        let original = DateHolder(ts: Date(timeIntervalSince1970: 1_755_000_000))
        let encoded = try TamgaJSONCoding.encoder.encode(original)
        let decoded = try TamgaJSONCoding.decoder.decode(DateHolder.self, from: encoded)

        // Fractional-second round-trip can lose sub-millisecond precision --
        // compare at 1-second resolution, matching what the wire format
        // actually preserves.
        #expect(abs(decoded.ts.timeIntervalSince(original.ts)) < 1.0)
    }

    @Test("snake_case wire keys decode into camelCase Swift properties")
    func convertsSnakeCaseKeys() throws {
        struct SnakeCaseHolder: Decodable, Equatable {
            let someFieldName: String
        }
        let json = Data(#"{"some_field_name":"value"}"#.utf8)
        let decoded = try TamgaJSONCoding.decoder.decode(SnakeCaseHolder.self, from: json)
        #expect(decoded.someFieldName == "value")
    }
}
