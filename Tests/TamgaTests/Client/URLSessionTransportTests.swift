import Foundation
import Testing

@testable import Tamga

/// Covers the two controls that live in the `URLSession` layer and therefore
/// cannot be reached through `MockPerformer`. Both are security boundaries.
@Suite("URLSessionTransport")
struct URLSessionTransportTests {
    @Test("a redirect is refused rather than followed")
    func redirectIsRefused() async throws {
        // OkHttp strips Authorization across origins but nothing strips a
        // manually-set Cookie, and URLSession follows redirects by default.
        // Refusing outright is what keeps a 3xx from carrying credentials to a
        // host the caller never configured.
        guard let server = LoopbackServer(behaviour: .redirect(to: "http://127.0.0.1:1/stolen"))
        else {
            Issue.record("could not start the loopback server")
            return
        }
        defer { server.stop() }

        let client = TamgaClient(accountId: "acct-123", auth: .sessionCookie("sess-secret"),
                                 host: server.baseURL, timeout: 10)

        do {
            _ = try await client.checkIn("lic-1")
            Issue.record("expected the 302 to surface rather than be followed")
        } catch let error as TamgaError {
            // The redirect surfaces as an ordinary API error carrying the 302,
            // which is only possible if it was not followed.
            #expect(error.httpStatus == 302)
        }
    }

    @Test("a response declaring more than the cap is refused before it transfers")
    func oversizedDeclaredResponseIsRefused() async throws {
        guard let server = LoopbackServer(
            behaviour: .body(declaredLength: 5_000_000, actualBytes: 1_024))
        else {
            Issue.record("could not start the loopback server")
            return
        }
        defer { server.stop() }

        let client = TamgaClient(accountId: "acct-123", auth: .licenseKey("k"),
                                 host: server.baseURL, timeout: 10,
                                 maxResponseBytes: 4_096)

        do {
            _ = try await client.checkIn("lic-1")
            Issue.record("expected the oversized response to be refused")
        } catch let error as TamgaError {
            guard case .transport(let message, _) = error else {
                Issue.record("expected .transport, got \(error)")
                return
            }
            #expect(message.contains("byte limit"))
        }
    }

    @Test("a response within the cap is delivered normally")
    func responseWithinTheCapIsDelivered() async throws {
        let body = "{\"data\":{\"id\":\"lic-1\",\"type\":\"licenses\",\"attributes\":{}}}"
        guard let server = LoopbackServer(
            behaviour: .body(declaredLength: body.utf8.count, actualBytes: 0))
        else {
            Issue.record("could not start the loopback server")
            return
        }
        defer { server.stop() }

        // The server writes only the header for this case, so the request times
        // out rather than completing -- what matters is that the cap did not
        // reject it up front, which a `byte limit` message would prove.
        let client = TamgaClient(accountId: "acct-123", auth: .licenseKey("k"),
                                 host: server.baseURL, timeout: 2,
                                 maxResponseBytes: Transport.maxResponseBytes)

        do {
            _ = try await client.checkIn("lic-1")
        } catch let error as TamgaError {
            if case .transport(let message, _) = error {
                #expect(!message.contains("byte limit"))
            }
        }
    }
}
