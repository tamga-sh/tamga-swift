import Foundation
import Testing

@testable import Tamga

@Suite("CanonicalJson")
struct CanonicalJsonTests {
    @Test("object keys are sorted alphabetically, not source order")
    func sortsObjectKeysAlphabetically() {
        let value = JSONValue.object(["zebra": .string("z"), "apple": .string("a"), "mango": .string("m")])
        #expect(CanonicalJson.serialize(value) == #"{"apple":"a","mango":"m","zebra":"z"}"#)
    }

    @Test("sorting is recursive at every nesting level")
    func sortsRecursively() {
        // Matches the exact worked example from Proof.swift's remarks:
        // dataset sorts before machine, and fingerprint sorts before id
        // within machine.
        let value = JSONValue.object([
            "machine": .object(["id": .string("m1"), "fingerprint": .string("fp1")]),
            "account": .object(["id": .string("a1")]),
            "dataset": .object(["z": .int(1), "a": .int(2)])
        ])
        let expected = #"""
        {"account":{"id":"a1"},"dataset":{"a":2,"z":1},"machine":{"fingerprint":"fp1","id":"m1"}}
        """#
        #expect(CanonicalJson.serialize(value) == expected)
    }

    @Test("arrays keep their original element order")
    func preservesArrayOrder() {
        let value = JSONValue.array([.int(3), .int(1), .int(2)])
        #expect(CanonicalJson.serialize(value) == "[3,1,2]")
    }

    @Test("integers serialize without a decimal point, distinct from doubles")
    func integersDoNotGetADecimalPoint() {
        // Regression: an earlier JSONValue design had a single .number(Double)
        // case, which would have reformatted a plain integer field (e.g. 5)
        // as "5.0" -- a byte that wouldn't match what the server signed.
        #expect(CanonicalJson.serialize(.int(5)) == "5")
        #expect(CanonicalJson.serialize(.double(5.5)) == "5.5")
    }

    @Test("keys are sorted by UTF-8 byte order")
    func sortsKeysByUTF8ByteOrder() {
        let value = JSONValue.object([
            "\u{10000}": .string("astral"), // 4-byte UTF-8
            "\u{E000}": .string("bmp-private-use"), // 3-byte UTF-8
            "a": .string("ascii") // 1-byte UTF-8
        ])
        let serialized = CanonicalJson.serialize(value)

        // Check the key VALUES' relative positions in the output, rather
        // than hardcoding the full escaped string -- documents intent
        // (ascii key sorts first, then the 3-byte BMP key, then the 4-byte
        // astral key) without being brittle to how the non-ASCII key
        // characters themselves get rendered.
        guard let asciiPos = serialized.range(of: "\"ascii\"")?.lowerBound,
              let bmpPos = serialized.range(of: "\"bmp-private-use\"")?.lowerBound,
              let astralPos = serialized.range(of: "\"astral\"")?.lowerBound
        else {
            Issue.record("expected all three key markers to be present in the serialized output")
            return
        }
        #expect(asciiPos < bmpPos)
        #expect(bmpPos < astralPos)
    }

    @Test("string escaping matches serde_json's default: quotes, backslashes, control chars, non-ASCII raw")
    func escapesStringsCorrectly() {
        #expect(CanonicalJson.serialize(.string("simple")) == #""simple""#)
        #expect(CanonicalJson.serialize(.string(#"has "quotes""#)) == #""has \"quotes\"""#)
        #expect(CanonicalJson.serialize(.string(#"back\slash"#)) == #""back\\slash""#)
        #expect(CanonicalJson.serialize(.string("line\nbreak")) == #""line\nbreak""#)
        #expect(CanonicalJson.serialize(.string("tab\ttab")) == #""tab\ttab""#)
        // Non-ASCII is emitted raw, NOT escaped to \uXXXX.
        #expect(CanonicalJson.serialize(.string("café 日本語 🎉")) == "\"café 日本語 🎉\"")
        // Forward slash is NOT escaped (serde_json doesn't escape it either).
        #expect(CanonicalJson.serialize(.string("a/b")) == #""a/b""#)
    }

    @Test("null and bool serialize as their JSON literals")
    func serializesNullAndBool() {
        #expect(CanonicalJson.serialize(.null) == "null")
        #expect(CanonicalJson.serialize(.bool(true)) == "true")
        #expect(CanonicalJson.serialize(.bool(false)) == "false")
    }

    @Test("output has no whitespace")
    func hasNoWhitespace() {
        let value = JSONValue.object(["a": .int(1), "b": .array([.int(1), .int(2)])])
        let serialized = CanonicalJson.serialize(value)
        #expect(!serialized.contains(" "))
        #expect(!serialized.contains("\n"))
    }
}
