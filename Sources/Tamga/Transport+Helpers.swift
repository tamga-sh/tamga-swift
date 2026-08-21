import Foundation

/// `Transport`'s pure helpers: version sanitizing, path-segment encoding,
/// retry eligibility and backoff timing.
///
/// Split out of `Transport.swift` because they are the parts with no I/O in
/// them, and so the parts a test can drive directly.
extension Transport {
    /// Filters a `Tamga-Version` value to the server's accepted character set
    /// and length.
    ///
    /// Mirrors the server's own filter-then-truncate order exactly: disallowed
    /// characters are dropped rather than replaced, and only then is the result
    /// truncated. Truncating first would produce a different string.
    static func sanitizeVersion(_ version: String?) -> String {
        guard let version else { return "" }
        var out = ""
        for character in version {
            guard out.count < maxAPIVersionLength else { break }
            let allowed = character.isASCII
                && (character.isLetter || character.isNumber || character == "." || character == "-")
            if allowed {
                out.append(character)
            }
        }
        return out
    }

    /// Characters that may appear literally in a path segment: RFC 3986's
    /// unreserved set. Everything else, `/` very much included, is escaped.
    private static let unreservedPathCharacters: CharacterSet = {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return allowed
    }()

    /// Percent-encodes one path segment so it cannot escape its position.
    ///
    /// Encoding alone is not enough: `.` and `..` are unreserved characters, so
    /// a segment consisting only of dots survives escaping and is still a
    /// dot-segment that URL resolution collapses -- which is exactly how an id
    /// of `../../evil` reached a different endpoint. Such a segment has its
    /// dots percent-encoded so it stays an ordinary, literal path component.
    static func encodePathSegment(_ segment: String) throws -> String {
        guard !segment.isEmpty else {
            // A caller-supplied empty id would otherwise collapse to `//` and
            // come back as an opaque 404 rather than an actionable error.
            throw TamgaError.transport(message: "A path segment cannot be empty.", underlying: nil)
        }
        guard let escaped = segment.addingPercentEncoding(
            withAllowedCharacters: unreservedPathCharacters) else {
            // Fails closed. This is the one function standing between a
            // caller-supplied id and the request path, so it must not degrade
            // to something that merely looks harmless.
            throw TamgaError.transport(message: "A path segment could not be encoded.",
                                       underlying: nil)
        }
        if escaped.allSatisfy({ $0 == "." }) {
            return String(repeating: "%2E", count: escaped.count)
        }
        return escaped
    }

    /// Whether a request is safe to repeat after a 429.
    static func isRetryable(method: String, path: String) -> Bool {
        if method == "GET" { return true }
        guard method == "POST" else { return false }
        return retryablePostSuffixes.contains { path.hasSuffix($0) }
    }

    /// Reads `Retry-After` as delta-seconds, returning `nil` when absent or
    /// unusable.
    ///
    /// The HTTP-date form is ignored deliberately. The server sends seconds,
    /// and misreading a date as a duration would be far worse than falling back
    /// to local backoff.
    static func parseRetryAfterSeconds(_ headerValue: String?) -> Int? {
        guard let trimmed = headerValue?.trimmingCharacters(in: .whitespaces), !trimmed.isEmpty,
              let seconds = Int(trimmed), seconds >= 0
        else {
            return nil
        }
        return seconds
    }

    /// How long to wait before the retry numbered `attempt`, zero-based.
    ///
    /// Prefers the server's `Retry-After` -- it knows when the bucket refills --
    /// but caps it, so a misconfigured or hostile proxy cannot park the caller
    /// for an hour on one header. Otherwise exponential backoff with jitter,
    /// because a fleet that all retries on the same schedule reconverges into
    /// the spike it was backing off from.
    static func retryDelayMilliseconds(attempt: Int, retryAfterSeconds: Int?,
                                       jitterMilliseconds: UInt64) -> UInt64 {
        if let retryAfterSeconds {
            return UInt64(min(retryAfterSeconds, maxRetryAfterSeconds)) * 1000
        }
        let shift = min(attempt, maxBackoffShift)
        return (UInt64(1) << UInt64(shift)) * 1000 + jitterMilliseconds
    }
}
