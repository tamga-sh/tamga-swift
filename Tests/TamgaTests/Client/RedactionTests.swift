import Foundation
import Testing

@testable import Tamga

/// Credentials must not appear in any textual rendering of the client.
///
/// Swift renders a type that declares no description by reflecting over its
/// stored properties, and reflection ignores access control -- `private` is a
/// compile-time restriction, not a runtime one. Without explicit redaction,
/// `print(client)` and `dump(client)` each print the raw license key. That
/// matters because `TamgaClient` is documented as a long-lived,
/// application-wide value, which is exactly what gets swept into app-state
/// logging, container dumps and crash-reporter context.
@Suite("Credential redaction")
struct RedactionTests {
    private static let secret = "SUPER-SECRET-LICENSE-KEY-XYZ"

    private func rendered(_ value: Any) -> [String] {
        var dumped = ""
        dump(value, to: &dumped)
        return ["\(value)", String(describing: value), String(reflecting: value), dumped]
    }

    @Test("a client never renders its credential")
    func clientNeverRendersItsCredential() {
        let client = TamgaClient(accountId: "acct-123", auth: .licenseKey(Self.secret),
                                 performer: MockPerformer())

        for rendering in rendered(client) {
            #expect(!rendering.contains(Self.secret))
        }
    }

    @Test("every auth form redacts its credential")
    func everyAuthFormRedactsItsCredential() {
        let forms: [AuthTransport] = [
            .bearer(Self.secret),
            .basicEmailPassword(email: "a@b.com", password: Self.secret),
            .basicToken(Self.secret),
            .basicLicenseKey(Self.secret),
            .licenseKey(Self.secret),
            .sessionCookie(Self.secret),
            .queryParameter(Self.secret)
        ]

        for form in forms {
            for rendering in rendered(form) {
                #expect(!rendering.contains(Self.secret), "\(form) leaked through a rendering")
            }
        }
    }

    @Test("redaction still identifies which auth form is in use")
    func redactionStillIdentifiesTheAuthForm() {
        // Redacting the secret should not make the value useless for debugging.
        #expect("\(AuthTransport.licenseKey(Self.secret))".contains("licenseKey"))
        #expect("\(AuthTransport.bearer(Self.secret))".contains("bearer"))
        #expect("\(AuthTransport.sessionCookie(Self.secret))".contains("sessionCookie"))
    }

    @Test("the credential still reaches the wire")
    func credentialStillReachesTheWire() async throws {
        // The whole point is redacting the rendering, not the request.
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(performer, auth: .licenseKey(Self.secret))
            .checkIn("lic-1")

        #expect(await performer.request(at: 0)?
            .value(forHTTPHeaderField: "Authorization") == "License \(Self.secret)")
    }
}
