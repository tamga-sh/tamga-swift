import Foundation

/// Minimal DER (Distinguished Encoding Rules) reader for the one thing this
/// SDK needs from ASN.1: pulling the named-curve OID out of an X.509
/// `SubjectPublicKeyInfo`'s `AlgorithmIdentifier`. Not a general-purpose
/// ASN.1 parser -- do not extend this ad hoc for unrelated DER shapes; if
/// another type ever needs real ASN.1 parsing, use a proper library instead
/// of growing this by hand.
///
/// Why this exists: confirmed directly (empirically, not from documentation)
/// that `CryptoKit`'s `P256.Signing.PublicKey(derRepresentation:)` does NOT
/// validate the curve OID in the `AlgorithmIdentifier` it parses -- only the
/// resulting coordinate byte length. A hand-crafted SPKI declaring the
/// secp256k1 curve OID but carrying a real P-256 point's raw coordinates
/// (same 65-byte x963 length) was silently accepted and parsed as if it
/// were a genuine P-256 key. This is the same curve-confusion bug class
/// this SDK family's own audit found live in tamga-python/go/dotnet's
/// generic `ECDsa`-based verifiers -- see `Ecdsa.swift`'s explicit guard,
/// which this type exists to support.
enum DER {
    struct Element {
        let tag: UInt8
        let content: ArraySlice<UInt8>
    }

    enum DERError: Error {
        case truncated
        case unsupportedLongFormLength
    }

    /// SEQUENCE tag (0x30).
    static let sequenceTag: UInt8 = 0x30
    /// OBJECT IDENTIFIER tag (0x06).
    static let objectIdentifierTag: UInt8 = 0x06

    /// Reads one TLV (tag-length-value) element starting at `bytes.startIndex`.
    /// Supports DER's short-form length and multi-byte long-form length (up
    /// to 4 length bytes, far more than any structure this SDK parses ever
    /// needs -- SPKI headers are a few dozen bytes at most).
    static func readElement(_ bytes: ArraySlice<UInt8>) throws -> (element: Element, rest: ArraySlice<UInt8>) {
        var index = bytes.startIndex
        guard index < bytes.endIndex else { throw DERError.truncated }
        let tag = bytes[index]
        index += 1

        guard index < bytes.endIndex else { throw DERError.truncated }
        let lengthByte = bytes[index]
        index += 1

        let length: Int
        if lengthByte & 0x80 == 0 {
            length = Int(lengthByte)
        } else {
            let lengthByteCount = Int(lengthByte & 0x7F)
            guard lengthByteCount > 0, lengthByteCount <= 4 else { throw DERError.unsupportedLongFormLength }
            guard bytes.endIndex - index >= lengthByteCount else { throw DERError.truncated }
            var value = 0
            for _ in 0..<lengthByteCount {
                value = (value << 8) | Int(bytes[index])
                index += 1
            }
            length = value
        }

        guard length >= 0, bytes.endIndex - index >= length else { throw DERError.truncated }
        let content = bytes[index..<(index + length)]
        return (Element(tag: tag, content: content), bytes[(index + length)...])
    }

    /// Extracts the named-curve OID's raw content bytes (no tag/length) from
    /// an X.509 `SubjectPublicKeyInfo`'s `AlgorithmIdentifier`, for the EC
    /// case specifically:
    /// `SEQUENCE { SEQUENCE { OID algorithm, OID namedCurve }, BIT STRING key }`.
    /// Returns `nil` if the input doesn't match this exact shape -- e.g. an
    /// RSA key's `AlgorithmIdentifier` parameters are `NULL`, not a second
    /// OID, so this correctly returns `nil` for RSA SPKI input rather than
    /// misreading it.
    static func ecNamedCurveOID(fromSubjectPublicKeyInfo der: some Sequence<UInt8>) -> [UInt8]? {
        let bytes = Array(der)[...]
        guard let (outer, _) = try? readElement(bytes), outer.tag == sequenceTag,
              let (algId, _) = try? readElement(outer.content), algId.tag == sequenceTag,
              let (algorithmOID, algIdRest) = try? readElement(algId.content),
              algorithmOID.tag == objectIdentifierTag,
              let (curveOID, _) = try? readElement(algIdRest),
              curveOID.tag == objectIdentifierTag
        else {
            return nil
        }
        return Array(curveOID.content)
    }
}
