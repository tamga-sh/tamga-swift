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
/// license, whereas an API error does.
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
    public static let defaultTimeout: TimeInterval = 30

    /// The page size `hasEntitlement` requests -- the server's maximum. It
    /// fetches a single page; see that method's note on the limitation.
    public static let entitlementLookupPageSize = 100

    /// The `Tamga-Version` sent unless overridden.
    public static let defaultAPIVersion = Transport.defaultAPIVersion

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
    ///   - maxRetries: How many times a rate-limited request is retried. Zero
    ///     disables retrying.
    ///   - timeout: Per-request timeout.
    public init(
        accountId: String,
        auth: AuthTransport,
        host: String = TamgaClient.defaultHost,
        apiVersion: String = TamgaClient.defaultAPIVersion,
        otp: String? = nil,
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
                  otp: otp, maxRetries: maxRetries,
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
    static let sdkVersion = "1.2.0"

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

    /// Validates a license by id without touching it, returning only the
    /// verdict.
    ///
    /// This is the one endpoint whose response is **flat**: there is no `data`
    /// envelope and no license resource, just the four validation fields at the
    /// top level.
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

    static func pageQuery(_ options: ListOptions) -> [URLQueryItem] {
        var query: [URLQueryItem] = []
        if options.limit > 0 {
            query.append(URLQueryItem(name: "limit", value: String(options.limit)))
        }
        if let after = options.after {
            query.append(URLQueryItem(name: "page[after]", value: after))
        }
        return query
    }

    /// Derives the next cursor for a page.
    ///
    /// These endpoints return no cursor metadata or links, so the cursor is
    /// synthesized: the last item's id, and only when the page came back full.
    /// A short or empty page means there is nothing further to fetch.
    static func synthesizeCursor<A>(_ resources: [JSONAPIResource<A>],
                                    options: ListOptions) -> String? {
        guard options.limit > 0, resources.count >= options.limit else { return nil }
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
