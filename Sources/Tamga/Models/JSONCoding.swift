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

/// Shared, pre-configured formatters -- `ISO8601DateFormatter` is safe for
/// concurrent read-only use (`.date(from:)`/`.string(from:)`) once
/// configured, since none of its `formatOptions`/etc. are ever mutated after
/// creation here. Avoids allocating a fresh formatter on every single
/// decode/encode call. `nonisolated(unsafe)` because `ISO8601DateFormatter`
/// (an `NSObject` subclass) isn't `Sendable`-audited by the SDK, even though
/// this particular usage pattern (configure once, never mutate, read-only
/// after) is safe -- confirmed by building under this package's
/// `swift-tools-version:6.0` Swift 6 language mode.
nonisolated(unsafe) private let iso8601FormatterWithFractionalSeconds: ISO8601DateFormatter = {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter
}()

nonisolated(unsafe) private let iso8601FormatterWithoutFractionalSeconds: ISO8601DateFormatter = {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter
}()

extension JSONDecoder.DateDecodingStrategy {
    /// ISO 8601 with optional fractional seconds -- `DateFormatter`/
    /// `ISO8601DateFormatter`'s default `.withInternetDateTime` option set
    /// rejects timestamps with a fractional-seconds component
    /// (`2026-08-12T10:00:00.123Z`), which the server emits. Falls back to
    /// the no-fractional-seconds form for timestamps that omit it.
    static let iso8601WithFractionalSeconds = JSONDecoder.DateDecodingStrategy.custom { decoder in
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)

        if let date = iso8601FormatterWithFractionalSeconds.date(from: string) {
            return date
        }
        if let date = iso8601FormatterWithoutFractionalSeconds.date(from: string) {
            return date
        }

        throw DecodingError.dataCorruptedError(
            in: container, debugDescription: "Expected ISO 8601 date string, got '\(string)'"
        )
    }
}

extension JSONEncoder.DateEncodingStrategy {
    static let iso8601WithFractionalSeconds = JSONEncoder.DateEncodingStrategy.custom { date, encoder in
        var container = encoder.singleValueContainer()
        try container.encode(iso8601FormatterWithFractionalSeconds.string(from: date))
    }
}
