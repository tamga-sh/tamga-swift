import Foundation
import Testing

@testable import Tamga

@Suite("JSONValue")
struct JSONValueTests {
    private func roundTrip(_ value: JSONValue) throws -> JSONValue {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    @Test("round-trips a string")
    func roundTripsString() throws {
        #expect(try roundTrip(.string("hello")) == .string("hello"))
    }

    @Test("round-trips an integer, distinct from a double")
    func roundTripsInteger() throws {
        #expect(try roundTrip(.int(42)) == .int(42))
    }

    @Test("round-trips a double")
    func roundTripsDouble() throws {
        #expect(try roundTrip(.double(3.5)) == .double(3.5))
    }

    @Test("round-trips bool values")
    func roundTripsBool() throws {
        #expect(try roundTrip(.bool(true)) == .bool(true))
        #expect(try roundTrip(.bool(false)) == .bool(false))
    }

    @Test("round-trips null")
    func roundTripsNull() throws {
        #expect(try roundTrip(.null) == .null)
    }

    @Test("round-trips a nested object")
    func roundTripsNestedObject() throws {
        let value = JSONValue.object(["a": .int(1), "b": .object(["c": .string("nested")])])
        #expect(try roundTrip(value) == value)
    }

    @Test("round-trips an array of mixed types")
    func roundTripsMixedArray() throws {
        let value = JSONValue.array([.int(1), .string("two"), .bool(true), .null])
        #expect(try roundTrip(value) == value)
    }

    @Test("decodes a wire integer as .int, not .double")
    func decodesWireIntegerAsInt() throws {
        // Regression: decoding must try Int64 before Double, or a wire
        // value like "5" would decode as .double(5.0) and silently lose
        // the "this was an integer" distinction -- see JSONValue.swift's
        // type-level remarks for why that matters for Proof's canonical
        // JSON re-serialization specifically.
        let decoded = try JSONDecoder().decode(JSONValue.self, from: Data("5".utf8))
        #expect(decoded == .int(5))
    }

    @Test("decodes a metadata-shaped dictionary end to end")
    func decodesMetadataDictionary() throws {
        let json = Data(#"{"seats":5,"tier":"pro","trial":false,"note":null}"#.utf8)
        let decoded = try JSONDecoder().decode([String: JSONValue].self, from: json)
        #expect(decoded["seats"] == .int(5))
        #expect(decoded["tier"] == .string("pro"))
        #expect(decoded["trial"] == .bool(false))
        #expect(decoded["note"] == .null)
    }
}
