import Foundation
import Testing

@testable import Tamga

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The artifact read/download surface. `artifact.read` was always in
/// `Role::LicenseToken`; `artifact.download` was granted (and its route added)
/// by `tamga-api@e6d317b`, which is what made the third of these three routes
/// reachable.
@Suite("Artifacts")
struct ArtifactTests {
    // MARK: - Fixtures

    /// A full attribute bag spelled exactly as the server emits it:
    /// `rename_all = "camelCase"` gives `redirectUrl`, while the explicit
    /// `#[serde(rename)]` on two fields gives `created`/`updated` rather than
    /// `createdAt`/`updatedAt`.
    static func artifactJSON(id: String = "art-1", redirectURL: String? = nil) -> String {
        let redirect = redirectURL.map { #""redirectUrl":"\#($0)","# } ?? ""
        return """
        {"data":{"id":"\(id)","type":"artifacts","attributes":{\
        "filename":"Acme-2.0.0.dmg","filetype":"dmg","filesize":3221225472,\
        "checksum":"sha256:abc","platform":"darwin","arch":"arm64",\
        "signature":"sig-xyz","status":"UPLOADED",\(redirect)\
        "metadata":{"channel":"stable"},\
        "created":"2026-08-01T00:00:00Z","updated":"2026-08-02T09:30:00.500Z"}}}
        """
    }

    static func artifactList(_ ids: [String]) -> String {
        let items = ids.map { id in
            """
            {"id":"\(id)","type":"artifacts","attributes":{"filename":"\(id).dmg",\
            "filetype":"dmg","filesize":10,"status":"UPLOADED","metadata":{},\
            "created":"2026-08-01T00:00:00Z","updated":"2026-08-01T00:00:00Z"}}
            """
        }.joined(separator: ",")
        return "{\"data\":[\(items)]}"
    }

    static let presigned =
        "https://storage.example.test/bucket/art-1?X-Amz-Signature=deadbeef&X-Amz-Expires=300"

    // MARK: - The wire-naming trap

    /// The whole bag decodes, which is the assertion that catches the
    /// `created`/`updated` vs `createdAt`/`updatedAt` confusion and the
    /// `redirectUrl` casing at once. A wrong name here does not throw -- every
    /// field is optional -- it silently decodes `nil`, which is exactly how
    /// `MachineAttributes` shipped a bug that made every machine read
    /// `.notStarted`.
    @Test("every attribute decodes under the shared snake-case decoder")
    func attributesDecode() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON())
        let artifact = try await TamgaClient.mocked(performer).getArtifact("art-1")

        #expect(artifact.id == "art-1")
        #expect(artifact.filename == "Acme-2.0.0.dmg")
        #expect(artifact.filetype == "dmg")
        #expect(artifact.filesize == 3_221_225_472)  // > Int32, so BIGINT matters
        #expect(artifact.checksum == "sha256:abc")
        #expect(artifact.platform == "darwin")
        #expect(artifact.arch == "arm64")
        #expect(artifact.signature == "sig-xyz")
        #expect(artifact.status == "UPLOADED")
        #expect(artifact.metadata?["channel"] == .string("stable"))
        #expect(artifact.created == Date(timeIntervalSince1970: 1_785_542_400))
        // Fractional seconds, which the plain `.withInternetDateTime` option set
        // rejects -- the shared decoder falls back for exactly this.
        #expect(artifact.updated == Date(timeIntervalSince1970: 1_785_663_000.5))
        #expect(artifact.redirectURL == nil)  // absent on show
    }

    /// Named separately because it is the field most likely to be "fixed" into
    /// `created_at` by someone generalising from `machines`/`licenses`.
    @Test("the timestamps are created/updated, not createdAt/updatedAt")
    func timestampsUseTheShortNames() async throws {
        let performer = MockPerformer()
        // The names the server does NOT use. If the decoder were reading these,
        // the short names above would have to be nil -- and vice versa.
        await performer.enqueue(body: """
        {"data":{"id":"art-1","type":"artifacts","attributes":{"filename":"a.dmg",\
        "createdAt":"2026-08-01T00:00:00Z","updatedAt":"2026-08-02T00:00:00Z"}}}
        """)
        let wrongNames = try await TamgaClient.mocked(performer).getArtifact("art-1")
        #expect(wrongNames.created == nil)
        #expect(wrongNames.updated == nil)

        let right = MockPerformer()
        await right.enqueue(body: Self.artifactJSON())
        let artifact = try await TamgaClient.mocked(right).getArtifact("art-1")
        #expect(artifact.created != nil)
        #expect(artifact.updated != nil)
    }

    /// The wire name is `redirectUrl`, and it decodes because
    /// `.convertFromSnakeCase` leaves a key with no underscore exactly as it
    /// found it.
    ///
    /// The snake_case spelling decodes too, and that is measured rather than
    /// assumed: the strategy rewrites `redirect_url` to `redirectUrl` and then
    /// matches the same property. So the decoder is lenient across both
    /// spellings here and the server's choice between them cannot break this
    /// client -- which is worth pinning, because it means a future server-side
    /// rename in either direction is a non-event, and because the obvious
    /// "defensive" `CodingKeys` would have destroyed exactly this property.
    @Test("both redirectUrl and redirect_url decode; the CodingKeys 'fix' would break it")
    func redirectURLSpelling() async throws {
        for key in ["redirectUrl", "redirect_url"] {
            let performer = MockPerformer()
            await performer.enqueue(body: """
            {"data":{"id":"art-1","type":"artifacts","attributes":{"filename":"a.dmg",\
            "\(key)":"\(Self.presigned)"}}}
            """)
            let download = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
            #expect(download.url.absoluteString == Self.presigned)
        }

        // The conversion that makes both work, stated directly.
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        struct Probe: Decodable { let redirectUrl: String? }
        let fromCamel = try decoder.decode(Probe.self, from: Data(#"{"redirectUrl":"a"}"#.utf8))
        let fromSnake = try decoder.decode(Probe.self, from: Data(#"{"redirect_url":"a"}"#.utf8))
        #expect(fromCamel.redirectUrl == "a")
        #expect(fromSnake.redirectUrl == "a")
    }

    // MARK: - Requests

    @Test("listing an artifact nests under the release and pages by keyset")
    func listRequestShape() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactList(["art-1", "art-2"]))
        let page = try await TamgaClient.mocked(performer)
            .listReleaseArtifacts(releaseId: "rel-9", options: ListOptions(after: "art-0", limit: 2))

        let url = try #require(await performer.request(at: 0)?.url?.absoluteString)
        #expect(url.contains("/v1/accounts/acct-123/releases/rel-9/artifacts"))
        #expect(url.contains("limit=2"))
        #expect(url.contains("page%5Bafter%5D=art-0"))
        #expect(page.items.map(\.id) == ["art-1", "art-2"])
        // A full page against the requested limit, so a cursor is synthesized.
        #expect(page.nextCursor == "art-2")
    }

    @Test("a short page ends pagination")
    func shortPageHasNoCursor() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactList(["art-1"]))
        let page = try await TamgaClient.mocked(performer)
            .listReleaseArtifacts(releaseId: "rel-9", options: ListOptions(limit: 10))
        #expect(page.nextCursor == nil)
    }

    /// Artifacts are addressed directly under the account for show and
    /// download, and only nested under the release for list. Getting that
    /// backwards is a 404 that looks like a missing artifact.
    @Test("show and download hang off the account, not the release")
    func showAndDownloadPathShape() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON())
        _ = try await TamgaClient.mocked(performer).getArtifact("art-1")
        let showURL = try #require(await performer.request(at: 0)?.url?.absoluteString)
        #expect(showURL.contains("/v1/accounts/acct-123/artifacts/art-1"))
        #expect(!showURL.contains("releases"))

        let downloader = MockPerformer()
        await downloader.enqueue(body: Self.artifactJSON(redirectURL: Self.presigned))
        _ = try await TamgaClient.mocked(downloader).downloadArtifact("art-1", ttl: 900)
        let downloadURL = try #require(await downloader.request(at: 0)?.url?.absoluteString)
        #expect(downloadURL.contains("/v1/accounts/acct-123/artifacts/art-1/actions/download"))
        #expect(downloadURL.contains("ttl=900"))
    }

    /// The `303` this client refuses is never requested in the first place.
    @Test("the download always asks for redirect=false")
    func downloadNeverAsksForARedirect() async throws {
        for ttl in [nil, 60, 604_800] as [Int?] {
            let performer = MockPerformer()
            await performer.enqueue(body: Self.artifactJSON(redirectURL: Self.presigned))
            _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1", ttl: ttl)
            let url = try #require(await performer.request(at: 0)?.url?.absoluteString)
            #expect(url.contains("redirect=false"))
            #expect(!url.contains("redirect=true"))
        }
    }

    @Test("no ttl means no ttl parameter, so the server picks its default")
    func omittedTTLSendsNothing() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON(redirectURL: Self.presigned))
        _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
        let url = try #require(await performer.request(at: 0)?.url?.absoluteString)
        #expect(!url.contains("ttl="))
    }

    // MARK: - ttl range

    @Test("a ttl outside the server's range is refused before the round trip",
          arguments: [0, 59, 604_801, -1, Int.max])
    func outOfRangeTTLIsRefusedLocally(_ ttl: Int) async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON(redirectURL: Self.presigned))

        do {
            _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1", ttl: ttl)
            Issue.record("expected \(ttl) to be refused")
        } catch let error as TamgaError {
            guard case .transport(let message, _) = error else {
                Issue.record("expected .transport, got \(error)")
                return
            }
            #expect(message.contains("ttl"))
        }
        // The point of checking locally: nothing was sent.
        #expect(await performer.requestCount == 0)
    }

    @Test("both ends of the accepted range are sent, not rejected",
          arguments: [60, 300, 604_800])
    func inRangeTTLIsSent(_ ttl: Int) async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON(redirectURL: Self.presigned))
        _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1", ttl: ttl)
        let url = try #require(await performer.request(at: 0)?.url?.absoluteString)
        #expect(url.contains("ttl=\(ttl)"))
    }

    @Test("the bounds match the server's own constants")
    func boundsMatchTheServer() {
        #expect(TamgaClient.minimumDownloadTTLSeconds == 60)
        #expect(TamgaClient.maximumDownloadTTLSeconds == 604_800)
    }

    // MARK: - Failure modes

    /// A 2xx with no URL is a server taking a path this call did not ask for.
    /// Handing back an `Artifact` with a nil URL would push that onto callers.
    @Test("a 2xx carrying no redirectUrl is a malformed response, not a nil URL")
    func missingRedirectURLThrows() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON())  // no redirectUrl
        do {
            _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
            Issue.record("expected a malformedResponse")
        } catch let error as TamgaError {
            guard case .malformedResponse = error else {
                Issue.record("expected .malformedResponse, got \(error)")
                return
            }
        }
    }

    @Test("an unparseable redirectUrl is refused rather than dropped")
    func unparseableRedirectURLThrows() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON(redirectURL: ""))
        await #expect(throws: TamgaError.self) {
            _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
        }
    }

    /// A `403` from this route is the release's read gate at least as often as
    /// it is the permission, since `enforce_release_access` runs after
    /// `require_download`. The SDK surfaces it as an ordinary API error and
    /// does not editorialise -- but it must not swallow it.
    @Test("a release-gate 403 surfaces as an API error with its server code")
    func releaseGateForbiddenSurfaces() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 403, body: """
        {"errors":[{"id":"e-1","status":"403","code":"FORBIDDEN","title":"Forbidden",\
        "detail":"Your license does not have the required entitlements to access this release"}]}
        """)
        do {
            _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
            Issue.record("expected a 403")
        } catch let error as TamgaError {
            #expect(error.httpStatus == 403)
            #expect(error.apiCode == "FORBIDDEN")
        }
    }

    /// A deployment with no object storage answers this, and it is not an auth
    /// problem -- worth keeping distinguishable from the 403 above.
    @Test("STORAGE_UNAVAILABLE surfaces as its own code")
    func storageUnavailableSurfaces() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 422, body: """
        {"errors":[{"id":"e-2","status":"422","code":"STORAGE_UNAVAILABLE",\
        "title":"Unprocessable","detail":"No storage backend is configured"}]}
        """)
        do {
            _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
            Issue.record("expected a 422")
        } catch let error as TamgaError {
            #expect(error.apiCode == "STORAGE_UNAVAILABLE")
            #expect(error.httpStatus == 422)
        }
    }

    /// If the server ever ignored `redirect=false` and answered `303` anyway,
    /// that must surface as an error rather than be followed. `throwIfError`
    /// treats anything outside 200..<300 as an error, so a `3xx` cannot be
    /// mistaken for success and silently decoded.
    @Test("a 303 is an error, never a followed hop")
    func redirectStatusIsAnError() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 303, body: "",
                                headers: ["Location": Self.presigned])
        do {
            _ = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
            Issue.record("expected the 303 to surface as an error")
        } catch let error as TamgaError {
            #expect(error.httpStatus == 303)
        }
        // One request. A followed redirect would have made two.
        #expect(await performer.requestCount == 1)
    }

    // MARK: - Credentials

    /// The credential goes to the API host and stops there. The presigned URL
    /// is handed back for the caller to fetch anonymously -- this SDK never
    /// requests it, which is what keeps the licence key off the storage host.
    @Test("the licence key reaches the API and never the storage URL")
    func credentialDoesNotFollowTheURL() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON(redirectURL: Self.presigned))
        let download = try await TamgaClient.mocked(performer, auth: .licenseKey("lic-secret"))
            .downloadArtifact("art-1")

        let request = try #require(await performer.request(at: 0))
        #expect(request.value(forHTTPHeaderField: "Authorization") == "License lic-secret")
        #expect(request.url?.host == "api.example.test")

        // Exactly one request was made, and it was to the API. The storage host
        // was never contacted by this SDK at all.
        #expect(await performer.requestCount == 1)
        #expect(download.url.host == "storage.example.test")
    }
}
