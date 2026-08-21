import Foundation
import Testing

@testable import Tamga

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The `Origin` header that makes session-cookie auth work at all.
///
/// Without it the server does not reject a cookie -- it *ignores* it
/// (`shared/auth/context.rs:277-289` returns `Ok(None)`), so the request goes
/// out as anonymous and comes back `401` complaining about missing
/// credentials. Nothing in the response says the cookie was the problem, which
/// is why this is worth pinning from both directions: the cookie transport
/// must send one, and the other six must not.
@Suite("Session-cookie Origin")
struct CookieOriginTests {
    private func header(_ request: URLRequest?, _ name: String) -> String? {
        request?.value(forHTTPHeaderField: name)
    }

    private func requestUsing(_ auth: AuthTransport, origin: String? = nil) async throws -> URLRequest? {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        let client = TamgaClient(
            accountId: "acct-123", auth: auth, host: "https://api.example.test",
            origin: origin, maxRetries: 0, performer: performer,
            jitterMilliseconds: { 0 })
        _ = try await client.checkIn("lic-1")
        return await performer.request(at: 0)
    }

    @Test("a session cookie travels with the server's default portal origin")
    func cookieSendsTheDefaultOrigin() async throws {
        let request = try await requestUsing(.sessionCookie("sess-1"))

        #expect(header(request, "Cookie") == "Tamga-Session=sess-1")
        #expect(header(request, "Origin") == "https://app.tamga.sh")
        #expect(TamgaClient.defaultPortalOrigin == "https://app.tamga.sh")
    }

    /// The server compares the header for exact equality against its
    /// `TAMGA_PORTAL_ORIGIN`, so a self-hosted portal origin has to go out
    /// byte for byte as configured -- no normalising, no trailing slash added
    /// or removed.
    @Test("a caller-supplied origin is sent verbatim")
    func customOriginIsSentVerbatim() async throws {
        let request = try await requestUsing(
            .sessionCookie("sess-1"), origin: "https://portal.example.test:8443")
        #expect(header(request, "Origin") == "https://portal.example.test:8443")
    }

    /// The narrowness is the feature. `quick_validate.rs:35` skips the
    /// `last_validated_at` write whenever an `Origin` is present at all --
    /// value irrelevant -- so a blanket header would silently stop
    /// `quickValidate` touching the licence for every caller.
    @Test("no other transport sends an Origin", arguments: [
        AuthTransport.bearer("tok-1"),
        AuthTransport.basicEmailPassword(email: "a@b.com", password: "pw"),
        AuthTransport.basicToken("tok-1"),
        AuthTransport.basicLicenseKey("lic-1"),
        AuthTransport.licenseKey("lic-1"),
        AuthTransport.queryParameter("tok-1")
    ])
    func otherTransportsSendNoOrigin(auth: AuthTransport) async throws {
        #expect(try await header(requestUsing(auth), "Origin") == nil)
    }

    /// Even when one is configured: the origin is scoped to the transport that
    /// needs it, not to the client.
    @Test("an origin configured alongside a non-cookie transport is not sent")
    func configuredOriginIsIgnoredForOtherTransports() async throws {
        let request = try await requestUsing(.licenseKey("lic-1"), origin: "https://portal.example.test")
        #expect(header(request, "Origin") == nil)
    }

    /// `/v1/health` is called anonymously on purpose. It sends no credential,
    /// so it sends no origin either -- the two travel together.
    @Test("the anonymous health route sends neither cookie nor origin")
    func healthSendsNeither() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: #"{"status":"ok"}"#)
        let client = TamgaClient(
            accountId: "acct-123", auth: .sessionCookie("sess-1"),
            host: "https://api.example.test", performer: performer)
        _ = try await client.health()

        let request = await performer.request(at: 0)
        #expect(header(request, "Cookie") == nil)
        #expect(header(request, "Origin") == nil)
    }

    /// The fix does not touch `AuthTransport`'s case list, so the credential's
    /// own wire form is byte-identical to before.
    @Test("the cookie's wire form is unchanged")
    func cookieWireFormIsUnchanged() async throws {
        let request = try await requestUsing(.sessionCookie("11111111-2222-3333-4444-555555555555"))
        #expect(header(request, "Cookie") == "Tamga-Session=11111111-2222-3333-4444-555555555555")
        #expect(header(request, "Authorization") == nil)
    }

    /// Redaction still holds: the case gained documentation and a companion
    /// header, not a new rendering path for its payload.
    @Test("the cookie transport still redacts its session id")
    func cookieStillRedacts() {
        let transport = AuthTransport.sessionCookie("secret-session")
        #expect(transport.description == "AuthTransport.sessionCookie(<redacted>)")
        #expect(String(describing: transport).contains("secret-session") == false)
    }
}
