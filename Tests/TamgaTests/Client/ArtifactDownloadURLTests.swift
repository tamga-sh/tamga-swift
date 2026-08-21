import Foundation
import Testing

@testable import Tamga

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// `redirectUrl` is the one value in this SDK that is a URL nobody here chose:
/// it arrives in a response body and the documented next step is to hand it to
/// a downloader. `URL(string:)` is not a guard for it -- these cases measure
/// exactly what it lets through -- so `TamgaClient.downloadArtifact(_:ttl:)`
/// checks the scheme itself.
///
/// Split out of `ArtifactTests` when that file passed the 400-line limit.
@Suite("Artifact download URL validation")
struct ArtifactDownloadURLTests {
    static func artifactJSON(redirectURL: String) -> String {
        ArtifactTests.artifactJSON(redirectURL: redirectURL)
    }

    /// `URL(string:)` is not a scheme check, and this is the one value in the
    /// SDK that is a URL nobody here chose. Each of these is accepted by
    /// `URL(string:)` -- `file:` even reports `isFileURL == true` -- and the
    /// documented next step for the result is `URLSession.download(from:)`, so
    /// a `file:` URL surviving here is a local-file read at a path the response
    /// body named.
    @Test("a non-http(s) redirectUrl is refused, however well-formed",
          arguments: [
            "file:///etc/passwd",
            "file:///Users/someone/.ssh/id_rsa",
            "javascript:alert(1)",
            "data:text/plain;base64,QQ==",
            "ftp://storage.example.test/b/a",
            "/etc/passwd",
            "C:\\Windows\\System32",
            "//storage.example.test/b/a",
            "https:///nohost"
          ])
    func nonHTTPRedirectURLIsRefused(_ candidate: String) async throws {
        // The premise: `URL(string:)` really does accept these.
        #expect(URL(string: candidate) != nil)

        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON(redirectURL: candidate))
        do {
            let download = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
            Issue.record("expected \(candidate) to be refused, got \(download.url)")
        } catch let error as TamgaError {
            guard case .malformedResponse = error else {
                Issue.record("expected .malformedResponse for \(candidate), got \(error)")
                return
            }
        }
    }

    /// Both HTTP schemes are accepted: `s3_endpoint` with
    /// `s3_force_path_style` lets an operator point storage at a plain-HTTP
    /// MinIO, and refusing that would break a legitimate deployment.
    ///
    /// The uppercase case is the one that would regress under a naive
    /// `scheme == "https"` -- `URL` does not normalise the scheme, so
    /// `URL(string: "HTTPS://h/a")?.scheme` is `"HTTPS"`.
    @Test("http, https and an uppercase scheme are all accepted",
          arguments: [
            "https://storage.example.test/b/a?X-Amz-Signature=x",
            "http://minio.internal:9000/b/a",
            "HTTPS://Storage.Example.Test/b/a",
            "HtTp://minio.internal:9000/b/a"
          ])
    func httpSchemesAreAccepted(_ candidate: String) async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.artifactJSON(redirectURL: candidate))
        let download = try await TamgaClient.mocked(performer).downloadArtifact("art-1")
        #expect(download.url.absoluteString == candidate)
        // The raw string is passed through unchanged; only `url` is checked.
        #expect(download.artifact.redirectURL == candidate)
    }
}
