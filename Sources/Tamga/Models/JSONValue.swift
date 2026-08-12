import Foundation

/// A minimal, fully `Codable`/`Equatable`/`Sendable` representation of an
/// arbitrary JSON value -- used for the caller-supplied `metadata` bags on
/// `License`/`Machine` and for `Proof`'s canonical-JSON-signed `dataset`
/// (arbitrary key/value data with no fixed schema), mirroring what
/// `Dictionary<string, JsonElement>`/`JsonNode` do in tamga-dotnet.
/// Foundation's `JSONSerialization` produces `Any`, which isn't `Equatable`
/// or `Sendable` -- this exists so metadata/datasets round-trip through
/// tests and value semantics cleanly instead of reaching for an untyped
/// escape hatch.
///
/// `.int` and `.double` are distinct cases, not one `.number(Double)` case:
/// collapsing them would silently reformat a plain integer field (e.g.
/// `5`) as a float (`5.0`) when re-serialized by `CanonicalJson` -- a byte
/// for the signed payload doesn't match what a caller's dataset actually
/// contained, breaking `Proof` signature verification for any dataset with
/// an integer field. Decoding tries `Int64` before `Double` so a wire value
/// like `"42"` decodes as `.int(42)`, not `.double(42.0)`.
///
/// NOT `indirect` at the type level -- `.object([String: JSONValue])` and
/// `.array([JSONValue])` already get their own heap indirection for free
/// from `Dictionary`/`Array`'s own COW buffer storage, so the enum itself
/// never needs boxing to be finite-sized. A type-level `indirect` would
/// force every case, including the common leaf cases (`.string`, `.int`,
/// `.bool`, ...), onto the heap unnecessarily -- confirmed removing it
/// entirely still builds and every `JSONValue` test still passes.
public enum JSONValue: Codable, Equatable, Sendable {
    case string(String)
    case int(Int64)
    case double(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .double(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}
