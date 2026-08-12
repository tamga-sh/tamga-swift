import Foundation

/// Shared `JSONDecoder`/`JSONEncoder` configuration for decoding server
/// resources -- ISO 8601 timestamps (the server's `DateTimeOffset`-shaped
/// fields), `snake_case` wire keys mapped to `camelCase` Swift properties.
/// Used by both `TamgaClient`'s response mapping and the offline
/// checkout/proof file parsers, so both paths decode identically -- see
/// `Checkout/LicenseFile.swift`/`Checkout/MachineFile.swift`.
enum TamgaJSONCoding {
    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601WithFractionalSeconds
        return decoder
    }()

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601WithFractionalSeconds
        return encoder
    }()
}

extension JSONDecoder.DateDecodingStrategy {
    /// ISO 8601 with optional fractional seconds -- `DateFormatter`/
    /// `ISO8601DateFormatter`'s default `.withInternetDateTime` option set
    /// rejects timestamps with a fractional-seconds component
    /// (`2026-08-12T10:00:00.123Z`), which the server emits. Falls back to
    /// the no-fractional-seconds form for timestamps that omit it.
    static let iso8601WithFractionalSeconds = JSONDecoder.DateDecodingStrategy.custom { decoder in
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)

        let withFractional = ISO8601DateFormatter()
        withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFractional.date(from: string) {
            return date
        }

        let withoutFractional = ISO8601DateFormatter()
        withoutFractional.formatOptions = [.withInternetDateTime]
        if let date = withoutFractional.date(from: string) {
            return date
        }

        throw DecodingError.dataCorruptedError(
            in: container, debugDescription: "Expected ISO 8601 date string, got '\(string)'"
        )
    }
}

extension JSONEncoder.DateEncodingStrategy {
    static let iso8601WithFractionalSeconds = JSONEncoder.DateEncodingStrategy.custom { date, encoder in
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var container = encoder.singleValueContainer()
        try container.encode(formatter.string(from: date))
    }
}
