import Foundation
import Testing

@testable import Tamga

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

@Suite("Transport")
struct TransportTests {
    private func header(_ request: URLRequest?, _ name: String) -> String? {
        request?.value(forHTTPHeaderField: name)
    }

    @Test("every auth form produces its documented wire representation")
    func authFormsProduceDocumentedWireRepresentation() async throws {
        struct Expectation {
            let auth: AuthTransport
            let headerName: String
            let headerValue: String
        }

        let cases = [
            Expectation(auth: .bearer("tok-1"),
                        headerName: "Authorization", headerValue: "Bearer tok-1"),
            Expectation(auth: .basicEmailPassword(email: "a@b.com", password: "pw"),
                        headerName: "Authorization",
                        headerValue: "Basic \(base64("a@b.com:pw"))"),
            Expectation(auth: .basicToken("tok-1"),
                        headerName: "Authorization",
                        headerValue: "Basic \(base64("tok-1:"))"),
            Expectation(auth: .basicLicenseKey("lic-1"),
                        headerName: "Authorization",
                        headerValue: "Basic \(base64("license:lic-1"))"),
            Expectation(auth: .licenseKey("lic-1"),
                        headerName: "Authorization", headerValue: "License lic-1"),
            Expectation(auth: .sessionCookie("sess-1"),
                        headerName: "Cookie", headerValue: "Tamga-Session=sess-1")
        ]

        for expectation in cases {
            let performer = MockPerformer()
            await performer.enqueue(body: Fixtures.license)
            _ = try await TamgaClient.mocked(performer, auth: expectation.auth).checkIn("lic-1")

            let request = await performer.request(at: 0)
            #expect(header(request, expectation.headerName) == expectation.headerValue)
        }
    }

    @Test("the trailing colon in basic-token auth is load-bearing")
    func basicTokenAuthKeepsItsTrailingColon() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(performer, auth: .basicToken("tok-1")).checkIn("lic-1")

        // base64("tok-1") and base64("tok-1:") differ, and only the latter is a
        // valid Basic credential with an empty password.
        let value = header(await performer.request(at: 0), "Authorization")
        #expect(value == "Basic \(base64("tok-1:"))")
        #expect(value != "Basic \(base64("tok-1"))")
    }

    @Test("query-parameter auth travels in the URL, not a header")
    func queryParameterAuthTravelsInTheUrl() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(performer, auth: .queryParameter("tok-1"))
            .checkIn("lic-1")

        let request = await performer.request(at: 0)
        #expect(request?.url?.query?.contains("token=tok-1") == true)
        #expect(header(request, "Authorization") == nil)
    }

    @Test("every request carries the version and agent headers")
    func everyRequestCarriesVersionAndAgentHeaders() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(performer).checkIn("lic-1")

        let request = await performer.request(at: 0)
        #expect(header(request, "Tamga-Version") == "1.8")
        #expect(header(request, "User-Agent")?.hasPrefix("tamga-swift/") == true)
    }

    @Test("the one-time-password header is sent only when configured")
    func oneTimePasswordHeaderIsSentOnlyWhenConfigured() async throws {
        let bare = MockPerformer()
        await bare.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(bare).checkIn("lic-1")
        #expect(header(await bare.request(at: 0), "Tamga-OTP") == nil)

        let withOtp = MockPerformer()
        await withOtp.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(withOtp, otp: "123456").checkIn("lic-1")
        #expect(header(await withOtp.request(at: 0), "Tamga-OTP") == "123456")
    }

    @Test("content-type is set only when there is a body")
    func contentTypeIsSetOnlyWhenThereIsABody() async throws {
        let bodyless = MockPerformer()
        await bodyless.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(bodyless).checkIn("lic-1")
        #expect(header(await bodyless.request(at: 0), "Content-Type") == nil)

        let withBody = MockPerformer()
        await withBody.enqueue(body: Fixtures.licenseWithMeta())
        _ = try await TamgaClient.mocked(withBody).validateByKey("K")
        #expect(header(await withBody.request(at: 0), "Content-Type") == "application/vnd.api+json")
    }

    @Test("the url is built under the account segment")
    func urlIsBuiltUnderTheAccountSegment() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        _ = try await TamgaClient.mocked(performer).checkIn("lic-1")

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/actions/check-in")
    }

    @Test("a slash in an id cannot escape its path segment")
    func slashInAnIdCannotEscapeItsPathSegment() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        // Without per-segment escaping this would resolve to a different
        // endpoint entirely.
        _ = try await TamgaClient.mocked(performer).checkIn("../../evil")

        // Assert on the wire form, not `URL.path`, which decodes percent
        // escapes and would show `..` even when `%2E%2E` is what is sent.
        let url = await performer.request(at: 0)?.url
        let wirePath = url.flatMap {
            URLComponents(url: $0, resolvingAgainstBaseURL: false)?.percentEncodedPath
        } ?? ""
        // The slashes are escaped, so `../../evil` stays one literal segment
        // and cannot climb the path.
        #expect(wirePath == "/v1/accounts/acct-123/licenses/..%2F..%2Fevil/actions/check-in")
        #expect(!wirePath.contains("/../"))
    }

    @Test("a path segment cannot escape via a slash or a dot-segment")
    func pathSegmentCannotEscape() {
        // A slash must not open a new segment.
        #expect(Transport.encodePathSegment("a/b") == "a%2Fb")
        // Dots are unreserved, so escaping alone leaves a dot-segment intact.
        // They are encoded explicitly so the component stays literal.
        #expect(Transport.encodePathSegment("..") == "%2E%2E")
        #expect(Transport.encodePathSegment(".") == "%2E")
        // An ordinary id is untouched, and a dot inside a longer id is fine.
        #expect(Transport.encodePathSegment("lic-1") == "lic-1")
        #expect(Transport.encodePathSegment("v1.2") == "v1.2")
        #expect(Transport.encodePathSegment("a b") == "a%20b")
    }

    @Test("sanitizeVersion drops disallowed characters")
    func sanitizeVersionDropsDisallowedCharacters() {
        #expect(Transport.sanitizeVersion("1.8") == "1.8")
        #expect(Transport.sanitizeVersion("1.8-beta_x") == "1.8-betax")
        #expect(Transport.sanitizeVersion("a b\tc") == "abc")
        #expect(Transport.sanitizeVersion(nil).isEmpty)
    }

    @Test("sanitizeVersion filters before truncating")
    func sanitizeVersionFiltersBeforeTruncating() {
        // 40 disallowed characters then "1.8". Filtering first keeps "1.8";
        // truncating first would keep 32 disallowed characters and yield "".
        let input = String(repeating: "!", count: 40) + "1.8"

        #expect(Transport.sanitizeVersion(input) == "1.8")
    }

    @Test("sanitizeVersion truncates to the accepted length")
    func sanitizeVersionTruncatesToTheAcceptedLength() {
        #expect(Transport.sanitizeVersion(String(repeating: "a", count: 50)).count
            == Transport.maxAPIVersionLength)
    }

    @Test("a bare host gains an https scheme and a trailing slash is trimmed")
    func bareHostGainsHttpsSchemeAndTrailingSlashIsTrimmed() {
        #expect(TamgaClient.normalizeHost("api.example.com") == "https://api.example.com")
        #expect(TamgaClient.normalizeHost("https://api.example.com/") == "https://api.example.com")
        // An explicit plaintext scheme is preserved rather than upgraded, so a
        // local mock server works without a test-only code path.
        #expect(TamgaClient.normalizeHost("http://127.0.0.1:8080") == "http://127.0.0.1:8080")
    }

    @Test("an oversized response body is refused")
    func oversizedResponseBodyIsRefused() async throws {
        // A hostile endpoint must not be able to drive the embedding
        // application out of memory. A timeout bounds duration, not size.
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)
        let client = TamgaClient.mocked(performer, maxResponseBytes: 8)

        await #expect(throws: TamgaError.self) {
            _ = try await client.checkIn("lic-1")
        }
    }

    private func base64(_ raw: String) -> String {
        Data(raw.utf8).base64EncodedString()
    }
}
