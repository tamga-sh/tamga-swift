import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// URL assembly, auth, headers, rate-limit retry, and error mapping.
///
/// Callers do not use this directly -- build a `TamgaClient` instead.
///
/// **Path segments are never concatenated.** Every caller-supplied id is added
/// as its own percent-encoded path component, so an id containing a slash or a
/// dot-segment cannot escape its position in the path.
///
/// **Rate limiting is handled here, not by the caller.** HTTP 429 is live
/// server-side, and the calls an embedded licensing client makes on a timer --
/// validate, heartbeat ping, check-in -- sit inside the server's tight per-IP
/// budget. Without backoff one throttled request becomes a sustained burst that
/// keeps the bucket empty and never recovers.
struct Transport: Sendable {
    /// The `Tamga-Version` sent unless overridden. The server falls back to
    /// this same value when the header is absent, but this SDK always sends it
    /// explicitly so a server-side API revision cannot silently reshape
    /// responses underneath a released SDK.
    static let defaultAPIVersion = "1.8"

    /// Default number of retries for a rate-limited request.
    static let defaultMaxRetries = 3

    /// Upper bound applied to a server-supplied `Retry-After`, in seconds.
    static let maxRetryAfterSeconds = 60

    /// Largest exponent used for backoff, so delay plateaus at 32s plus jitter.
    static let maxBackoffShift = 5

    /// Maximum accepted length of a sanitized `Tamga-Version` value.
    static let maxAPIVersionLength = 32

    /// Ceiling on how many bytes of a response body are accepted.
    ///
    /// Without a cap, a compromised endpoint can drive the embedding
    /// application out of memory simply by answering with a very large body.
    /// A timeout bounds how long a response may take, not how large it may be.
    /// 32 MiB is far above any legitimate response -- the largest thing this
    /// API returns is a checkout certificate measured in kilobytes.
    static let maxResponseBytes = 32 * 1024 * 1024

    /// The `POST` paths safe to repeat after a 429: effectively idempotent, and
    /// precisely the calls a client makes on a timer.
    ///
    /// Creates are deliberately absent. Retrying `POST /machines` risks a
    /// second activation burning a second seat, and only the caller knows
    /// whether that is acceptable.
    ///
    /// Matching is by suffix, not substring. `ping-heartbeat` and
    /// `reset-heartbeat` therefore do **not** match `/actions/ping` -- only a
    /// process ping does.
    static let retryablePostSuffixes = [
        "/actions/validate",
        "/actions/validate-key",
        "/actions/check-in",
        "/actions/check-out",
        "/actions/ping"
    ]

    private let performer: any HTTPRequestPerforming
    private let host: String
    private let accountId: String
    private let apiVersion: String
    private let otp: String?
    private let userAgent: String
    private let auth: AuthTransport
    private let maxRetries: Int
    private let maxResponseBytes: Int
    /// Injected so retry backoff is deterministic under test. Returns the
    /// jitter to add, in milliseconds.
    private let jitterMilliseconds: @Sendable () -> UInt64

    init(
        performer: any HTTPRequestPerforming,
        host: String,
        accountId: String,
        apiVersion: String,
        otp: String?,
        userAgent: String,
        auth: AuthTransport,
        maxRetries: Int,
        maxResponseBytes: Int = Transport.maxResponseBytes,
        jitterMilliseconds: @escaping @Sendable () -> UInt64 = { UInt64.random(in: 0..<1000) }
    ) {
        self.performer = performer
        self.host = host
        self.accountId = accountId
        self.apiVersion = apiVersion
        self.otp = otp
        self.userAgent = userAgent
        self.auth = auth
        self.maxRetries = maxRetries
        self.maxResponseBytes = maxResponseBytes
        self.jitterMilliseconds = jitterMilliseconds
    }

    // MARK: - Pure helpers

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

    // MARK: - Requests

    func getJSON(_ segments: [String], query: [URLQueryItem] = []) async throws -> Data {
        try await send(method: "GET", segments: segments, query: query, body: nil,
                       accept: "application/vnd.api+json")
    }

    func postJSON(_ segments: [String], body: JSONValue?) async throws -> Data {
        try await send(method: "POST", segments: segments, query: [], body: body,
                       accept: "application/vnd.api+json")
    }

    func delete(_ segments: [String]) async throws {
        _ = try await send(method: "DELETE", segments: segments, query: [], body: nil,
                           accept: "application/vnd.api+json")
    }

    func getText(_ segments: [String], query: [URLQueryItem]) async throws -> String {
        let data = try await send(method: "GET", segments: segments, query: query, body: nil,
                                  accept: "application/octet-stream")
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func send(method: String, segments: [String], query: [URLQueryItem],
                      body: JSONValue?, accept: String) async throws -> Data {
        let encodedBody: Data? = try body.map { value in
            do {
                return try TamgaJSONCoding.encoder.encode(value)
            } catch {
                throw TamgaError.transport(message: "Failed to encode the request body.",
                                           underlying: error)
            }
        }
        let path = "/" + segments.joined(separator: "/")
        let retryable = Self.isRetryable(method: method, path: path)
        let request = try buildRequest(method: method, segments: segments, query: query,
                                       body: encodedBody, accept: accept)

        var attempt = 0
        while true {
            let (data, response) = try await perform(request)

            if response.statusCode != 429 || !retryable || attempt >= maxRetries {
                try throwIfError(data: data, response: response)
                return data
            }

            let delay = Self.retryDelayMilliseconds(
                attempt: attempt,
                retryAfterSeconds: Self.parseRetryAfterSeconds(
                    response.value(forHTTPHeaderField: "Retry-After")),
                jitterMilliseconds: jitterMilliseconds()
            )
            do {
                try await Task.sleep(nanoseconds: delay * 1_000_000)
            } catch {
                throw TamgaError.transport(
                    message: "Cancelled while backing off from a rate limit.", underlying: error)
            }
            attempt += 1
        }
    }

    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let (data, response) = try await performer.perform(request)
            guard data.count <= maxResponseBytes else {
                throw TamgaError.transport(
                    message: "Server response body exceeded this client's "
                        + "\(maxResponseBytes) byte limit.", underlying: nil)
            }
            return (data, response)
        } catch let error as TamgaError {
            throw error
        } catch {
            throw TamgaError.transport(message: "Request failed.", underlying: error)
        }
    }

    private func buildRequest(method: String, segments: [String], query: [URLQueryItem],
                              body: Data?, accept: String) throws -> URLRequest {
        // The host is validated here rather than in `TamgaClient.init`, so an
        // unusable host surfaces as a real error instead of forcing the
        // initializer to either trap or become throwing.
        guard let baseURL = URL(string: host) else {
            throw TamgaError.transport(message: "Host is not a valid URL: \(host)",
                                       underlying: nil)
        }
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw TamgaError.transport(message: "Could not build a request URL.", underlying: nil)
        }

        // Every segment is percent-encoded individually and the path is
        // assembled from the encoded forms. `URL.appendPathComponent` is NOT
        // safe here: it leaves both `/` and dot-segments intact, so an id of
        // `../../evil` produced `.../licenses/../../evil/actions/check-in` and
        // called an entirely different endpoint.
        let allSegments = ["v1", "accounts", accountId] + segments
        let encoded = try allSegments.map(Self.encodePathSegment)
        let basePath = components.percentEncodedPath.hasSuffix("/")
            ? String(components.percentEncodedPath.dropLast())
            : components.percentEncodedPath
        components.percentEncodedPath = basePath + "/" + encoded.joined(separator: "/")

        var items = query
        if let authItem = auth.queryItem {
            items.append(authItem)
        }
        if !items.isEmpty {
            components.queryItems = items
        }
        guard let url = components.url else {
            throw TamgaError.transport(message: "Could not build a request URL.", underlying: nil)
        }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.setValue(accept, forHTTPHeaderField: "Accept")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(Self.sanitizeVersion(apiVersion), forHTTPHeaderField: "Tamga-Version")
        if let otp, !otp.isEmpty {
            request.setValue(otp, forHTTPHeaderField: "Tamga-OTP")
        }
        // Content-Type only when there is a body, so a bodyless POST does not
        // advertise a payload it is not sending.
        if body != nil {
            request.setValue("application/vnd.api+json", forHTTPHeaderField: "Content-Type")
        }
        if let header = auth.header {
            request.setValue(header.value, forHTTPHeaderField: header.name)
        }
        return request
    }

    /// Converts a non-2xx response into a `TamgaError.api`.
    ///
    /// The body is untrusted input from the network. An unreadable body, a
    /// non-JSON:API body, and an empty `errors` array all degrade to a
    /// synthetic `UNKNOWN` code rather than throwing a decode failure that
    /// would mask the real HTTP status.
    private func throwIfError(data: Data, response: HTTPURLResponse) throws {
        guard !(200..<300).contains(response.statusCode) else { return }

        let metadata = ResponseMetadata(response: response)
        let entry = (try? JSONDecoder().decode(ErrorDocument.self, from: data))?.errors?.first

        throw TamgaError.api(TamgaError.APIError(
            code: entry?.code.flatMap { $0.isEmpty ? nil : $0 } ?? TamgaError.APIError.unknownCode,
            httpStatus: response.statusCode,
            detail: entry?.detail,
            title: entry?.title,
            id: entry?.id,
            pointer: entry?.source?.pointer,
            responseMetadata: metadata
        ))
    }
}

// MARK: - Redaction

/// Redacts the whole transport rather than relying on `AuthTransport`'s own
/// redaction alone.
///
/// A parent struct with no description of its own is rendered by reflecting
/// over its stored properties, so `Transport` would otherwise expose its
/// `auth` field for `dump` to walk. Redacting at both levels means neither one
/// has to be the only thing standing between a credential and a log line.
extension Transport: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String { "Transport(host: \(host), accountId: \(accountId), auth: <redacted>)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: []) }
}
