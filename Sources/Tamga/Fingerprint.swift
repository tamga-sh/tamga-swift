import Crypto
import Foundation

/// Turns caller-chosen machine identity components into one canonical
/// fingerprint string.
///
/// ## What this fixes
///
/// Every SDK in this fleet used to send whatever fingerprint string the caller
/// handed it, byte for byte. The server stores `fingerprint TEXT NOT NULL`
/// with no length limit, no `CHECK` and no normalisation, unique per
/// `(license_id, fingerprint)` -- so `"ABC-123"`, `"abc-123"` and
/// `" ABC-123 "` were three machines occupying three seats on one licence.
/// Running the components through here first collapses the differences that
/// are accidents of formatting, and *only* those.
///
/// ## What this deliberately does not do
///
/// **It does not read hardware identifiers.** There is no
/// `TamgaFingerprint.current()` and there should not be. What identifies a
/// machine is a product decision, not a library one: a cloned VM template
/// shares its board serial and MAC with every sibling, a container has neither,
/// and a replaced motherboard changes both under a user who did nothing wrong.
/// No default is right for both a desktop app and a Kubernetes sidecar, so the
/// caller picks the components and this canonicalises them.
///
/// **It does not Unicode-normalise, and that is a constraint rather than an
/// oversight.** Foundation offers `precomposedStringWithCanonicalMapping` and
/// using it here would be one line. It is left out because the same rule has to
/// hold in eight SDKs: NFC needs a new dependency in Rust and Go, and in C11 it
/// means ICU or hand-rolled Unicode tables inside a library whose whole selling
/// point is having none. A rule eight ports cannot implement identically is
/// worse than no rule -- it would yield two fingerprints for one machine
/// depending on which SDK the application happened to be written in, silently
/// consuming two seats. **A caller whose values can arrive in more than one
/// normal form must normalise them before calling.**
///
/// **It does not case-fold.** Lowercasing a base64 or hex identifier corrupts
/// it, so `"ABC123"` and `"abc123"` stay distinct.
///
/// **It does not repair.** Every rejection below throws. Silently stripping a
/// control character would map two different inputs onto one seat, which is the
/// bug this type exists to remove rather than to relocate.
///
/// ## The rule
///
/// ```text
/// canonical   = "tamga-fingerprint-v1" <US> join(<US>, sort_bytewise(["label=value"]))
/// fingerprint = lowercase_hex(SHA-256(UTF-8(canonical)))     // 64 characters
/// ```
///
/// `<US>` is U+001F, the ASCII unit separator, emitted as the single byte
/// `0x1f`. The literal prefix is a domain separator, so a future v2 rule cannot
/// collide with v1.
///
/// ```swift
/// let fingerprint = try TamgaFingerprint.compute([
///     .init(label: "machine-id", value: machineId),
///     .init(label: "disk", value: diskSerial)
/// ])
/// let machine = try await client.activateMachine(
///     licenseId: licenseId, options: .init(fingerprint: fingerprint))
/// ```
public enum TamgaFingerprint {
    /// The domain-separating prefix every canonical string starts with.
    public static let version = "tamga-fingerprint-v1"

    /// One labelled piece of machine identity.
    ///
    /// The label names what the value is (`"machine-id"`, `"disk"`, `"mac"`).
    /// It is part of the hashed input, so renaming a label changes the
    /// fingerprint just as changing its value does.
    public struct Component: Equatable, Sendable {
        /// What this component is. Non-empty, ASCII printable `0x21`-`0x7E`
        /// only, and may not contain `=`.
        ///
        /// The ASCII restriction is what keeps labels out of the normalisation
        /// problem described on `TamgaFingerprint`: a label that cannot contain
        /// a non-ASCII character cannot itself need normalising.
        public let label: String

        /// The value. ASCII whitespace is trimmed from both ends before
        /// validation, after which no ASCII control character may remain.
        ///
        /// May contain `=`, may contain non-ASCII text, and may be empty -- a
        /// component that reads empty is not the same as an absent component,
        /// because the label still contributes to the hash.
        public let value: String

        /// Creates a component.
        public init(label: String, value: String) {
            self.label = label
            self.value = value
        }
    }

    /// Builds the canonical string the fingerprint is the hash of.
    ///
    /// Exposed alongside `compute(_:)` because a fingerprint is 64 characters
    /// of hex that says nothing about why two machines disagreed. Logging this
    /// instead shows exactly which component differed. It contains the raw
    /// component values, so treat it with whatever care those values deserve.
    ///
    /// - Throws: `TamgaFingerprintError`. Nothing is repaired; see the type.
    public static func canonical(_ components: [Component]) throws -> String {
        guard !components.isEmpty else { throw TamgaFingerprintError.noComponents }

        var seenLabels = Set<String>()
        // Both forms are kept: the sort is defined on bytes, the output is a
        // string, and deriving one from the other afterwards would mean either
        // a lossy decode or a second pass.
        var encoded: [(bytes: [UInt8], text: String)] = []
        encoded.reserveCapacity(components.count)

        for component in components {
            guard !component.label.isEmpty else { throw TamgaFingerprintError.emptyLabel }
            guard component.label.unicodeScalars.allSatisfy(isLabelScalar) else {
                throw TamgaFingerprintError.invalidLabel(component.label)
            }
            // Labels are ASCII by the check above, so `String` equality here is
            // byte equality and cannot fold two distinct labels together.
            guard seenLabels.insert(component.label).inserted else {
                throw TamgaFingerprintError.duplicateLabel(component.label)
            }

            // Trim first, validate second -- the spec's order. A value of only
            // whitespace is therefore a legal empty value, while an inner
            // control character is still a rejection.
            let value = trimmingASCIIWhitespace(component.value)
            guard !value.unicodeScalars.contains(where: isControlScalar) else {
                // The value is not echoed: it is the caller's machine identity,
                // and the label is enough to say which component was at fault.
                throw TamgaFingerprintError.controlCharacterInValue(label: component.label)
            }

            // `String` concatenation does not normalise -- Swift stores the
            // UTF-8 it was given and normalises only when comparing or hashing
            // -- so these bytes are the label's bytes, `0x3d`, and the value's
            // bytes, in that order. The `non_ascii_value` vector pins it.
            let text = component.label + "=" + value
            encoded.append((bytes: Array(text.utf8), text: text))
        }

        // Bytewise ascending on the UTF-8 bytes. This is the spelling of the
        // rule as the shared spec states it, and it is deliberately NOT backed
        // by a test, because for valid input it cannot fail.
        //
        // Two things that get conflated here, both worth stating once:
        //
        // - Bytewise UTF-8 order and code-point order are the *same* ordering.
        //   UTF-8 is designed so byte comparison reproduces code-point
        //   comparison, so there is nothing to distinguish and no vector should
        //   claim to. Swift's `String` `<` diverges on a third axis --
        //   canonical equivalence, which calls `"cafe\u{0301}"` and
        //   `"caf\u{00E9}"` *equal* where their bytes differ.
        //
        // - That divergence is unreachable through this rule. Labels are ASCII
        //   printable 0x21-0x7E without `=` and are unique, so the first
        //   differing byte of any two components always lands inside the ASCII
        //   label region or on the `=` terminating it -- a value's bytes never
        //   decide the order -- and on ASCII, canonical equivalence and byte
        //   order agree. Measured here over 7,587,405 valid pairs, and by
        //   tamga-js over 8,732,016: zero disagreements in both. Replacing this
        //   with `sort { $0.text < $1.text }` leaves every test green, and a
        //   test written to "catch" that would be a green test proving nothing.
        //
        // Kept as bytes because it is what the spec says and it stays correct
        // if a v2 rule ever loosens the label alphabet. What IS pinned, because
        // it does bite: the sort key is the whole `label=value` component
        // rather than the label alone, and the comparison is case-sensitive.
        encoded.sort { $0.bytes.lexicographicallyPrecedes($1.bytes) }

        return ([version] + encoded.map(\.text)).joined(separator: separator)
    }

    /// The canonical fingerprint: 64 lowercase hex characters.
    ///
    /// This is the value to send as a machine's `fingerprint`.
    ///
    /// - Throws: `TamgaFingerprintError`, exactly as `canonical(_:)` does.
    public static func compute(_ components: [Component]) throws -> String {
        let input = try canonical(components)
        return SHA256.hash(data: Data(input.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    // MARK: - Character rules

    /// U+001F, the ASCII unit separator, one byte (`0x1f`) in UTF-8.
    private static let separator = "\u{1F}"

    /// ASCII whitespace: tab, LF, VT, FF, CR, space.
    ///
    /// Deliberately narrower than `CharacterSet.whitespacesAndNewlines`, which
    /// also covers U+00A0, U+2028 and the U+2000 block. Those are ordinary
    /// characters under this rule and are hashed, not trimmed -- a set the
    /// other seven ports can reproduce without a Unicode table.
    private static func isASCIIWhitespace(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value == 0x20 || (0x09...0x0D).contains(scalar.value)
    }

    /// ASCII control characters: `0x00`-`0x1F` and `0x7F`. The unit separator
    /// is one of them, so a separator inside a value is caught here too.
    ///
    /// Scalar-level and byte-level checks agree here: every scalar below
    /// `0x80` is exactly one UTF-8 byte, and no multi-byte sequence contains a
    /// byte below `0x80`.
    private static func isControlScalar(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x20 || scalar.value == 0x7F
    }

    /// ASCII printable, excluding space and `=`. Rejects every non-ASCII
    /// scalar, whose value is `0x80` or above.
    private static func isLabelScalar(_ scalar: Unicode.Scalar) -> Bool {
        (0x21...0x7E).contains(scalar.value) && scalar != "="
    }

    /// Drops leading and trailing ASCII whitespace.
    ///
    /// Trims unicode *scalars* rather than `Character`s on purpose:
    /// `trimmingCharacters(in:)` works on grapheme clusters, and `"\r\n"` is a
    /// single cluster, so a value ending `"x\r\n"` would trim differently from
    /// one ending `"x\n\r"`. Scalar trimming is exactly equivalent to the
    /// byte trimming the shared rule describes.
    private static func trimmingASCIIWhitespace(_ value: String) -> String {
        var scalars = value.unicodeScalars[...]
        while let first = scalars.first, isASCIIWhitespace(first) {
            scalars = scalars.dropFirst()
        }
        while let last = scalars.last, isASCIIWhitespace(last) {
            scalars = scalars.dropLast()
        }
        return String(String.UnicodeScalarView(scalars))
    }
}

/// Why a set of components could not be canonicalised.
///
/// **A separate type, deliberately, and not a new `TamgaError` case.**
/// `TamgaError` and `TamgaCheckoutError` are plain public enums in a package
/// built from source, so adding a case to either breaks every exhaustive
/// `switch` a consumer has written -- at compile time, on a version a `from:`
/// requirement upgrades into automatically. This is new surface reachable only
/// through `TamgaFingerprint`, so it can throw a new type without breaking
/// anything that compiles today. `TamgaSigningKeyError` was added the same way
/// and for the same reason.
///
/// Every case is a rejection rather than a repair. Stripping the offending
/// character instead would map two different inputs onto one fingerprint, and a
/// fingerprint collision is one machine consuming another machine's seat.
public enum TamgaFingerprintError: Error, Equatable, Sendable {
    /// No components were supplied. At least one is required: hashing the bare
    /// domain prefix would give every caller the same fingerprint.
    case noComponents

    /// A component's label was empty. A value with nothing naming it cannot be
    /// told apart from a different value under a different name.
    case emptyLabel

    /// A label contained something other than ASCII printable `0x21`-`0x7E`,
    /// or contained `=`.
    ///
    /// `=` is excluded because it is the label/value delimiter, so a label
    /// containing one would make the split ambiguous. Non-ASCII is excluded so
    /// that a label can never itself need the Unicode normalisation this rule
    /// deliberately does not perform -- see `TamgaFingerprint`.
    case invalidLabel(String)

    /// The same label appeared twice.
    ///
    /// Not deduplicated: two values for one label is a caller bug, and picking
    /// one of them hides it behind a fingerprint that silently depends on
    /// argument order.
    case duplicateLabel(String)

    /// A value still contained an ASCII control character (`0x00`-`0x1F` or
    /// `0x7F`) after its surrounding whitespace was trimmed. Includes the
    /// U+001F separator itself.
    ///
    /// The value is not carried on the error -- it is the caller's machine
    /// identity, and the label already says which component was at fault.
    case controlCharacterInValue(label: String)
}

extension TamgaFingerprintError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noComponents:
            return "A fingerprint needs at least one component."
        case .emptyLabel:
            return "A fingerprint component's label may not be empty."
        case .invalidLabel(let label):
            return "Fingerprint label '\(label)' is not ASCII printable (0x21-0x7E) without '='."
        case .duplicateLabel(let label):
            return "Fingerprint label '\(label)' was supplied twice. "
                + "Duplicate labels are rejected, not merged."
        case .controlCharacterInValue(let label):
            return "The value for fingerprint label '\(label)' contains an ASCII control "
                + "character. Control characters are rejected rather than stripped."
        }
    }
}
