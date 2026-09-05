import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The Tamga API client: one `async` method per server endpoint.
///
/// ```swift
/// let client = TamgaClient(accountId: "acct-123", auth: .licenseKey(key))
/// let result = try await client.validateByKey(key)
/// if result.meta.code == .expired { promptForRenewal() }
/// ```
///
/// A client is a value type and `Sendable`, so it can be shared freely across
/// tasks. Create one per application rather than one per call, so the
/// underlying session's connection pool is reused.
///
/// Every method throws `TamgaError`. The distinction between its `.transport`
/// and `.api` cases matters: a transport failure says nothing about the
/// license, whereas an API error does. Match on `TamgaError.apiCode` against the
/// constants in `TamgaAPIErrorCode`, never on `detail`.
///
/// **Authentication is enforced, and license-key auth is off by default.** The
/// server only accepts `AuthTransport.licenseKey` / `.basicLicenseKey` when the
/// license's policy sets `authentication_strategy` to `LICENSE` or `MIXED`; the
/// column defaults to `TOKEN`, and `NONE` behaves like `TOKEN` at that gate.
/// Against a default policy every call made with a license key fails with
/// `401 LICENSE_NOT_ALLOWED` -- a configuration precondition, not a transient
/// error, so retrying or prompting for another key accomplishes nothing.
///
/// HTTP 429 is retried transparently for safe requests. Machine creation is
/// deliberately excluded, so a rate-limited activation surfaces rather than
/// silently burning a second seat.
///
/// Offline verification does not go through this type and needs no client at
/// all -- see `LicenseFile`, `MachineFile` and `MachineProof`.
public struct TamgaClient: Sendable {
    /// The production API host, used unless another is supplied.
    public static let defaultHost = "https://api.tamga.sh"

    /// Default per-request timeout.
    ///
    /// Deliberately longer than the server's own 30-second `TimeoutLayer`. When
    /// the two are equal a slow request races them, and the local timeout
    /// usually wins -- which throws away the server's `504` and, with it, the
    /// `x-request-id` that is the only thing linking a slow-request report back
    /// to a server-side trace.
    public static let defaultTimeout: TimeInterval = 45

    /// The page size requested when a caller names none -- the server's maximum.
    ///
    /// Sent explicitly rather than relying on the server's own default of 25.
    /// That default is invisible on the wire (these routes emit neither
    /// `meta.page` nor `links`), so page fullness is the only pagination signal
    /// and it cannot be read without knowing the page size that was asked for.
    public static let defaultPageSize = 100

    /// The page size `hasEntitlement` requests -- the server's maximum. It
    /// fetches a single page; see that method's note on the limitation.
    public static let entitlementLookupPageSize = 100

    /// The `Tamga-Version` sent unless overridden.
    public static let defaultAPIVersion = Transport.defaultAPIVersion

    /// The `Origin` sent alongside a session-cookie credential when the caller
    /// names none: the server's own `TAMGA_PORTAL_ORIGIN` default,
    /// `https://app.tamga.sh` (`config.rs:256-258`).
    ///
    /// A self-hosted server that sets a different portal origin needs the
    /// matching value passed as `origin:`; the server compares the header for
    /// exact equality, so a differing scheme, port or trailing slash fails the
    /// same way a missing header does.
    public static let defaultPortalOrigin = Transport.defaultPortalOrigin

    /// How many times a rate-limited request is retried unless overridden.
    public static let defaultMaxRetries = Transport.defaultMaxRetries

    /// Ceiling on how many bytes of a response body are accepted.
    public static let defaultMaxResponseBytes = Transport.maxResponseBytes

    let transport: Transport
    let entitlementCache: EntitlementCache

    /// Creates a client.
    ///
    /// - Parameters:
    ///   - accountId: Always required, in every server mode. There is no mode
    ///     where the account segment may be omitted.
    ///   - auth: The single credential form to send. `.licenseKey` is the right
    ///     default for an embedded client.
    ///   - host: Accepts a bare host or a full URL. A trailing slash is
    ///     trimmed and an explicit `http://` scheme is preserved rather than
    ///     upgraded, so a local mock server works without a test-only code
    ///     path.
    ///   - apiVersion: The `Tamga-Version` header. Override only deliberately.
    ///   - otp: A TOTP code, sent as `Tamga-OTP` on every request.
    ///   - origin: The `Origin` header value sent **only** with
    ///     `AuthTransport.sessionCookie`, defaulting to
    ///     `defaultPortalOrigin`. Cookie auth does not work without it: the
    ///     server downgrades a cookie-bearing request whose `Origin` does not
    ///     equal its configured portal origin to *unauthenticated*
    ///     (`shared/auth/context.rs:277-289`), which then surfaces as a `401`
    ///     saying no credential was supplied rather than that the cookie was
    ///     refused. Ignored by the other six transports on purpose -- an
    ///     `Origin` on `quickValidate` suppresses its `last_validated_at`
    ///     write (`quick_validate.rs:35-37`).
    ///   - maxRetries: How many times a rate-limited request is retried. Zero
    ///     disables retrying.
    ///   - timeout: Per-request timeout.
    public init(
        accountId: String,
        auth: AuthTransport,
        host: String = TamgaClient.defaultHost,
        apiVersion: String = TamgaClient.defaultAPIVersion,
        otp: String? = nil,
        origin: String? = nil,
        maxRetries: Int = TamgaClient.defaultMaxRetries,
        timeout: TimeInterval = TamgaClient.defaultTimeout,
        maxResponseBytes: Int = TamgaClient.defaultMaxResponseBytes
    ) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        // SECURITY: redirects are not followed.
        //
        // This client only ever calls a small fixed set of paths under one
        // configured host, so a 3xx is never a legitimate response. Following
        // one is also unsafe: a redirect can carry credentials to a host the
        // caller never configured, and the session-cookie form in particular
        // is not protected by any framework-level stripping.
        configuration.httpShouldSetCookies = false
        // timeoutIntervalForRequest resets on every chunk received, so on its own it only guards
        // against total silence -- a server trickling a byte every 25 seconds keeps resetting it
        // and is otherwise bounded only by the platform default resource timeout of seven days.
        configuration.timeoutIntervalForResource = timeout * 4
        self.init(accountId: accountId, auth: auth, host: host, apiVersion: apiVersion,
                  otp: otp, origin: origin, maxRetries: maxRetries,
                  performer: URLSessionTransport(configuration: configuration,
                                                 maxResponseBytes: maxResponseBytes),
                  maxResponseBytes: maxResponseBytes)
    }

    /// Creates a client over a caller-supplied request performer.
    ///
    /// This is the seam tests use to run without a network. A caller supplying
    /// their own performer owns its redirect, timeout and TLS behaviour.
    public init(
        accountId: String,
        auth: AuthTransport,
        host: String = TamgaClient.defaultHost,
        apiVersion: String = TamgaClient.defaultAPIVersion,
        otp: String? = nil,
        origin: String? = nil,
        maxRetries: Int = TamgaClient.defaultMaxRetries,
        performer: any HTTPRequestPerforming,
        maxResponseBytes: Int = TamgaClient.defaultMaxResponseBytes,
        jitterMilliseconds: @escaping @Sendable () -> UInt64 = { UInt64.random(in: 0..<1000) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.transport = Transport(
            performer: performer,
            host: Self.normalizeHost(host),
            accountId: accountId,
            apiVersion: apiVersion,
            otp: otp,
            userAgent: Self.userAgent,
            auth: auth,
            origin: origin,
            maxRetries: max(0, maxRetries),
            maxResponseBytes: maxResponseBytes,
            jitterMilliseconds: jitterMilliseconds
        )
        self.entitlementCache = EntitlementCache(now: now)
    }

    static func normalizeHost(_ host: String) -> String {
        var trimmed = host.trimmingCharacters(in: .whitespaces)
        while trimmed.hasSuffix("/") {
            trimmed.removeLast()
        }
        if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
            return trimmed
        }
        return "https://\(trimmed)"
    }

    private static let userAgent = "tamga-swift/\(sdkVersion)"

    /// This SDK's version, reported in `User-Agent`.
    static let sdkVersion = "1.3.3" // x-release-please-version

    // MARK: - Licenses

    /// Validates a license by its raw key.
    ///
    /// This endpoint takes no scope -- use `validateById` for scoped
    /// validation.
    public func validateByKey(_ key: String) async throws -> ValidationResult {
        let data = try await transport.postJSON(
            ["licenses", "actions", "validate-key"],
            body: .object(["key": .string(key)])
        )
        return try Self.decodeValidation(data)
    }

    /// Validates a license by id, optionally constrained by a `Scope`.
    public func validateById(
        _ licenseId: String,
        options: ValidateOptions = ValidateOptions()
    ) async throws -> ValidationResult {
        let data = try await transport.postJSON(
            ["licenses", licenseId, "actions", "validate"],
            body: options.requestBody
        )
        return try Self.decodeValidation(data)
    }

    /// Validates a license by id, returning only the verdict.
    ///
    /// This is the one endpoint whose response is **flat**: there is no `data`
    /// envelope and no license resource, just the four validation fields at the
    /// top level.
    ///
    /// **This does touch the license.** Earlier revisions of this doc claimed
    /// the opposite. The route writes `last_validated_at` on every call, with
    /// exactly one exception: it skips the write when the request carries an
    /// `Origin` header. It has no `skip_touch` of its own, and the response is
    /// byte-identical either way, so a caller cannot tell which happened.
    ///
    /// Two consequences worth planning around:
    ///
    /// - **To validate without side effects, use `validateById` with
    ///   `ValidateOptions(skipTouch: true)`.** That is the only route that
    ///   honours the request.
    /// - **Anything that puts an `Origin` on the request silently disables the
    ///   write.** The check is `headers.contains_key(ORIGIN)`
    ///   (`quick_validate.rs:35`) -- presence, not value. A proxy in front of
    ///   this SDK does it, a browser does it, and so does this SDK itself for
    ///   exactly one configuration: `AuthTransport.sessionCookie`, which cannot
    ///   authenticate at all without that header. Under that transport
    ///   `last_validated_at` stays null -- which keeps a never-activated
    ///   license reporting `INACTIVE` and keeps the check-in-overdue worker
    ///   firing against `created_at` forever. The other six transports send no
    ///   `Origin` and are unaffected. Checking in does not substitute; that
    ///   writes a different column.
    public func quickValidate(_ licenseId: String) async throws -> ValidationMeta {
        let data = try await transport.getJSON(["licenses", licenseId, "actions", "validate"])
        return try Self.decode(ValidationMetaWire.self, from: data).flattened
    }

    /// Checks a license in.
    ///
    /// Gate this on the policy's `requireCheckIn` rather than calling it
    /// unconditionally and catching `CHECK_IN_NOT_REQUIRED`.
    public func checkIn(_ licenseId: String) async throws -> License {
        let data = try await transport.postJSON(
            ["licenses", licenseId, "actions", "check-in"], body: nil)
        return License.fromResource(
            try Self.decode(DataEnvelope<LicenseAttributes>.self, from: data).data)
    }

    // MARK: - Checkout

    /// Downloads an offline `.lic` certificate and returns its PEM text.
    ///
    /// Verify the result with `LicenseFile`, which needs no network access.
    public func checkOutLicense(
        _ licenseId: String,
        options: CheckOutOptions = CheckOutOptions()
    ) async throws -> String {
        try await checkOut(["licenses", licenseId, "actions", "check-out"], options: options)
    }

    /// Downloads an offline `.machine` certificate and returns its PEM text.
    ///
    /// Verify the result with `MachineFile`, passing the owning license's
    /// scheme -- the algorithm comes from the license, never from the file's
    /// own `alg` field.
    public func checkOutMachine(
        _ machineId: String,
        options: CheckOutOptions = CheckOutOptions()
    ) async throws -> String {
        try await checkOut(["machines", machineId, "actions", "check-out"], options: options)
    }

    private func checkOut(_ segments: [String], options: CheckOutOptions) async throws -> String {
        try options.validate()
        if options.usePost {
            let data = try await transport.postJSON(segments, body: options.requestBody)
            let envelope = try Self.decode(DataEnvelope<CheckoutFileAttributes>.self, from: data)
            return envelope.data.attributes?.certificate ?? ""
        }
        var query = [URLQueryItem(name: "encrypt", value: options.encrypt ? "true" : "false")]
        if let ttl = options.ttl {
            query.append(URLQueryItem(name: "ttl", value: String(ttl)))
        }
        return try await transport.getText(segments, query: query)
    }

    // MARK: - Decoding helpers

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try TamgaJSONCoding.decoder.decode(type, from: data)
        } catch {
            throw TamgaError.malformedResponse(
                message: "Could not decode the server's response: \(error)", underlying: error)
        }
    }

    static func decodeValidation(_ data: Data) throws -> ValidationResult {
        let envelope = try decode(
            DataMetaEnvelope<LicenseAttributes, ValidationMetaWire>.self, from: data)
        let meta = envelope.meta?.flattened
            ?? ValidationMeta(ts: nil, valid: false, detail: nil, code: .unknown(""))
        return ValidationResult(license: License.fromResource(envelope.data), meta: meta)
    }

    /// The page size a request actually asks for.
    ///
    /// An unset or non-positive `limit` becomes `defaultPageSize` rather than
    /// being omitted, and an over-large one is clamped to it. Both cases used to
    /// truncate silently: omitting `limit` let the server apply its own default
    /// of 25 while `synthesizeCursor` compared the returned count against a
    /// different number, so a genuinely full page read as a short one and
    /// pagination stopped after the first 25 rows.
    static func effectiveLimit(_ options: ListOptions) -> Int {
        options.limit > 0 ? min(options.limit, defaultPageSize) : defaultPageSize
    }

    static func pageQuery(_ options: ListOptions) -> [URLQueryItem] {
        var query = [URLQueryItem(name: "limit", value: String(effectiveLimit(options)))]
        if let after = options.after {
            query.append(URLQueryItem(name: "page[after]", value: after))
        }
        return query
    }

    /// Derives the next cursor for a page.
    ///
    /// These endpoints return no cursor metadata or links, so the cursor is
    /// synthesized: the last item's id, and only when the page came back full
    /// against the page size actually requested. A short or empty page means
    /// there is nothing further to fetch.
    ///
    /// Only valid where keyset pagination really works -- components, not
    /// entitlements. See `listEntitlements`.
    static func synthesizeCursor<A>(_ resources: [JSONAPIResource<A>],
                                    options: ListOptions) -> String? {
        guard resources.count >= effectiveLimit(options) else { return nil }
        return resources.last?.id
    }
}

// MARK: - Redaction

/// Redacts the client, which is the value most likely to be logged.
///
/// `TamgaClient` is documented as a long-lived, application-wide value, which
/// makes it exactly what gets captured by app-state logging, container dumps
/// and crash-reporter context. See `AuthTransport`'s redaction note for why
/// access control does not help here.
extension TamgaClient: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "TamgaClient(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }
}
