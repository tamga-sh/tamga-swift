import Foundation

/// Recursively alphabetically-key-sorted, whitespace-free JSON serialization
/// of a `JSONValue` tree -- reproduces `serde_json::Value`'s
/// `BTreeMap`-backed serialization order (see `MachineProof`'s remarks).
/// Arrays keep their original element order (JSON arrays are ordered by
/// spec; only object keys get sorted).
enum CanonicalJson {
    static func serialize(_ value: JSONValue) -> String {
        var output = ""
        write(value, into: &output)
        return output
    }

    private static func write(_ value: JSONValue, into output: inout String) {
        switch value {
        case .null:
            output += "null"
        case .bool(let value):
            output += value ? "true" : "false"
        case .int(let value):
            output += String(value)
        case .double(let value):
            // NOTE: uses Swift's default shortest-round-trip Double
            // formatting, not a byte-for-byte port of Rust's ryu algorithm.
            // Both target the same "shortest decimal that round-trips to
            // the exact same IEEE 754 bit pattern" property, so common
            // values (e.g. whole numbers, simple decimals) format
            // identically -- but this is not exhaustively verified against
            // serde_json across every float edge case. Prefer .int for
            // whole-number dataset fields where possible.
            output += String(value)
        case .string(let value):
            writeEscapedString(value, into: &output)
        case .array(let elements):
            writeArray(elements, into: &output)
        case .object(let fields):
            writeObject(fields, into: &output)
        }
    }

    private static func writeArray(_ elements: [JSONValue], into output: inout String) {
        output += "["
        for (index, element) in elements.enumerated() {
            if index > 0 { output += "," }
            write(element, into: &output)
        }
        output += "]"
    }

    private static func writeObject(_ fields: [String: JSONValue], into output: inout String) {
        output += "{"
        // Sort by UTF-8 byte order explicitly, not Swift's default String
        // comparison. This SDK family's own audit found a live,
        // demonstrable divergence in tamga-js's canonicalJson.ts (its
        // default UTF-16-code-unit comparison disagreed with Rust's
        // BTreeMap<String,_> byte-wise order for astral-plane characters).
        // Checked directly whether Swift's default String comparison
        // (Unicode-canonical-equivalence-aware, not raw code units) has the
        // same failure mode: several adversarial pairs (BMP-private-use vs
        // astral, precomposed vs decomposed combining forms) did NOT
        // diverge from UTF-8 byte order in that check. Sorting by .utf8
        // explicitly is kept anyway -- matching Rust's BTreeMap<String, _>
        // ordering (defined as UTF-8 byte-lexicographic) is the actual
        // requirement here, not an incidental property of whatever Swift's
        // default comparator happens to do for the pairs tested so far.
        let sortedKeys = fields.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        for (index, key) in sortedKeys.enumerated() {
            if index > 0 { output += "," }
            writeEscapedString(key, into: &output)
            output += ":"
            // fields[key] can't actually be nil (key came from fields.keys),
            // but an `if let` here avoids a force-unwrap for a lookup the
            // compiler can't itself prove is total.
            if let fieldValue = fields[key] {
                write(fieldValue, into: &output)
            }
        }
        output += "}"
    }

    /// JSON string escaping matching serde_json's default: `"` and `\` are
    /// escaped, the standard short escapes (`\n`/`\r`/`\t`/`\u{08}`/`\u{0C}`)
    /// are used for their respective control characters, remaining control
    /// characters (0x00-0x1F) become `\u00XX`, and everything else --
    /// including non-ASCII characters -- is emitted as raw UTF-8, NOT
    /// escaped to `\uXXXX`. serde_json does not escape `/`.
    private static func writeEscapedString(_ string: String, into output: inout String) {
        output += "\""
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\"": output += "\\\""
            case "\\": output += "\\\\"
            case "\u{08}": output += "\\b"
            case "\u{0C}": output += "\\f"
            case "\n": output += "\\n"
            case "\r": output += "\\r"
            case "\t": output += "\\t"
            default:
                if scalar.value < 0x20 {
                    output += String(format: "\\u%04x", scalar.value)
                } else {
                    output.unicodeScalars.append(scalar)
                }
            }
        }
        output += "\""
    }
}
