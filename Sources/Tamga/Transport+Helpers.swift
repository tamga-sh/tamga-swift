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

extension Transport {
    /// Which shape of route a request is for.
    ///
    /// One value rather than two independent flags, because the two properties are
    /// not independent: the only route that skips the account prefix is also the
    /// only one that must skip the credential, and "account-scoped but anonymous"
    /// is not a combination that exists.
    enum RouteScope: Equatable, Sendable {
        /// Under `/v1/accounts/{accountId}`, carrying the configured credential.
        /// Every route but one.
        case account

        /// A bare `/v1/...` path on the public route list, sent **with no
        /// credential at all**. Only `GET /v1/health`.
        ///
        /// **The anonymity is a correctness requirement, not a saving.** The
        /// server's auth middleware resolves the request's credential *before* it
        /// consults the public-route list, and propagates a resolution failure with
        /// `?` -- so an unusable credential rejects a public route just as hard as a
        /// private one (`require_auth.rs:120-127`).
        ///
        /// Whether resolution even runs for a path with no `{account_id}` segment
        /// depends on the server's mode, and the dangerous one is the default.
        /// In **multiplayer** the account id comes from the path, `/v1/health` has
        /// none, and resolution short-circuits to "unauthenticated" before touching
        /// the database (`context.rs:293-297`). In **singleplayer** -- which is the
        /// `#[default]` (`config.rs:11-12`) -- the account id comes from
        /// configuration instead, so it is present for *every* path including this
        /// one, the credential really is looked up, and a licence key under a
        /// default policy comes back as
        /// `Err(401 LICENSE_NOT_ALLOWED)` (`license_lookup.rs:83-84`) because
        /// `authentication_strategy` defaults to `TOKEN`.
        ///
        /// The result would be a health probe that fails for exactly the callers
        /// whose credential is the thing in question -- destroying the one property
        /// that makes it worth calling. Sending nothing costs nothing: the route is
        /// public, returns no account data, and is exempt from the host check.
        ///
        /// This is a deliberate exception to the fleet contract's "credentials are
        /// always sent" rule, and the only one.
        case publicRoot

        /// Whether a request on this route carries the configured credential.
        var sendsCredential: Bool { self == .account }
    }
}
