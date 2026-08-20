import Foundation

/// One authentication scheme applied to an outgoing request.
///
/// The server accepts seven forms and tries them in a fixed order. This SDK
/// deliberately sends **exactly one** -- whichever the caller configured --
/// rather than replicating that fallback chain. `.licenseKey` is the right
/// default for an embedded client.
///
/// Credentials are sent on every request, including endpoints where the server
/// does not enforce authentication today, so callers stay forward-compatible
/// with enforcement landing.
///
/// **Tokens are opaque strings.** The server documents `tok-`/`prod-`/`env-`/
/// `activ-`/`lic-` prefixes per token type, but every issued token currently
/// gets the `tok-` prefix regardless of its type. Never build prefix-based type
/// detection against that documented-but-unimplemented convention.
public enum AuthTransport: Sendable, Equatable {
    /// `Authorization: Bearer <token>`.
    case bearer(String)
    /// `Authorization: Basic base64("<email>:<password>")`.
    case basicEmailPassword(email: String, password: String)
    /// `Authorization: Basic base64("<token>:")` -- the token as the username
    /// with an empty password. The trailing colon is load-bearing: without it
    /// the credential is a different, invalid string.
    case basicToken(String)
    /// `Authorization: Basic base64("license:<key>")`.
    case basicLicenseKey(String)
    /// `Authorization: License <key>` -- the primary transport for an embedded
    /// client validating against a raw license key.
    case licenseKey(String)
    /// `Cookie: Tamga-Session=<uuid>`.
    ///
    /// Provided for completeness. This form is browser and portal oriented --
    /// the server pairs it with an `Origin` check -- and is rarely the right
    /// choice for a non-browser consumer.
    case sessionCookie(String)
    /// `?token=<token>`.
    ///
    /// The server also accepts `?auth=` as a synonym; this sends `token`,
    /// mirroring the bearer semantics it substitutes for. Prefer a header form
    /// where possible: query strings are far more likely to be captured in
    /// proxy logs and referrer headers than an `Authorization` header is.
    case queryParameter(String)

    /// The header this transport contributes, if it is a header-based form.
    var header: (name: String, value: String)? {
        switch self {
        case .bearer(let token):
            return ("Authorization", "Bearer \(token)")
        case .basicEmailPassword(let email, let password):
            return ("Authorization", "Basic \(Self.base64("\(email):\(password)"))")
        case .basicToken(let token):
            return ("Authorization", "Basic \(Self.base64("\(token):"))")
        case .basicLicenseKey(let key):
            return ("Authorization", "Basic \(Self.base64("license:\(key)"))")
        case .licenseKey(let key):
            return ("Authorization", "License \(key)")
        case .sessionCookie(let sessionId):
            return ("Cookie", "Tamga-Session=\(sessionId)")
        case .queryParameter:
            return nil
        }
    }

    /// The query item this transport contributes, if it is the query-parameter
    /// form.
    var queryItem: URLQueryItem? {
        if case .queryParameter(let token) = self {
            return URLQueryItem(name: "token", value: token)
        }
        return nil
    }

    private static func base64(_ raw: String) -> String {
        Data(raw.utf8).base64EncodedString()
    }
}

// MARK: - Redaction

/// Keeps the credential out of any textual rendering of this value.
///
/// Swift synthesizes a description for a type that declares none by reflecting
/// over its stored properties, and reflection does not respect access control:
/// `private` is a compile-time restriction, not a runtime one. Without these
/// conformances, `print(client)`, `"\(client)"`, `String(describing:)` and
/// `dump(client)` each render the raw license key, bearer token or session id
/// in cleartext -- verified, not assumed.
///
/// That matters more than it first appears, because `TamgaClient` is documented
/// as a long-lived, application-wide value. Exactly that kind of object gets
/// swept into generic app-state logging, dependency-container dumps, crash
/// reporter context, or a `po client` during support triage.
///
/// All three conformances are needed. `CustomStringConvertible` alone fixes
/// interpolation and `print`, but `dump` keeps recursing into the associated
/// value until `customMirror` reports no children.
extension AuthTransport: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The transport's form, never its credential.
    public var description: String {
        switch self {
        case .bearer:
            return "AuthTransport.bearer(<redacted>)"
        case .basicEmailPassword:
            return "AuthTransport.basicEmailPassword(<redacted>)"
        case .basicToken:
            return "AuthTransport.basicToken(<redacted>)"
        case .basicLicenseKey:
            return "AuthTransport.basicLicenseKey(<redacted>)"
        case .licenseKey:
            return "AuthTransport.licenseKey(<redacted>)"
        case .sessionCookie:
            return "AuthTransport.sessionCookie(<redacted>)"
        case .queryParameter:
            return "AuthTransport.queryParameter(<redacted>)"
        }
    }

    public var debugDescription: String { description }

    /// An empty mirror, so `dump` cannot walk past `description` into the
    /// associated value.
    public var customMirror: Mirror { Mirror(self, children: []) }
}
