import Foundation
import Testing

@testable import Tamga

@Suite("Health probe")
struct HealthTests {
    @Test("health is requested without the account prefix every other route carries")
    func healthSkipsTheAccountPrefix() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.health)

        let status = try await TamgaClient.mocked(performer).health()

        // The whole reason no SDK could reach this route: the URL builder used
        // to prepend /v1/accounts/{id} unconditionally.
        #expect(await performer.request(at: 0)?.url?.path == "/v1/health")
        #expect(status.status == "ok")
        #expect(status.version == "1.8.3")
        #expect(status.uptimeSeconds == 4210)
    }

    @Test("health sends no credential at all")
    func healthSendsNoCredential() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.health)

        _ = try await TamgaClient.mocked(performer, auth: .bearer("tok-1")).health()

        // The server resolves the credential before consulting its public-route
        // list, so an unusable one rejects this route too -- and in the default
        // singleplayer mode a licence key under a default policy IS unusable.
        // A probe that fails when the credential is the thing in question is
        // worthless, so it goes out anonymously.
        #expect(await performer.request(at: 0)?
            .value(forHTTPHeaderField: "Authorization") == nil)
        // Not application/vnd.api+json: the body is a plain object.
        #expect(await performer.request(at: 0)?
            .value(forHTTPHeaderField: "Accept") == "application/json")
    }

    @Test("query-parameter auth does not leak a token into the health URL")
    func healthDoesNotLeakAQueryToken() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.health)

        _ = try await TamgaClient.mocked(performer, auth: .queryParameter("tok-2")).health()

        // The sharpest form of the rule: the query transport would otherwise put
        // the credential in a URL that gets pasted into support tickets.
        let url = await performer.request(at: 0)?.url
        #expect(url?.query == nil)
        #expect(url?.absoluteString.contains("tok-2") == false)
    }

    @Test("every other route still carries the credential")
    func otherRoutesStillAuthenticate() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)

        _ = try await TamgaClient.mocked(performer, auth: .bearer("tok-1")).getLicense("lic-1")

        // The anonymous path is one route, not a new default.
        #expect(await performer.request(at: 0)?
            .value(forHTTPHeaderField: "Authorization") == "Bearer tok-1")
    }

    @Test("an unknown status string still decodes")
    func unknownHealthStatusDecodes() async throws {
        let performer = MockPerformer()
        // A probe whose job is answering when things are wrong must not fail to
        // decode the day the answer stops being "ok".
        await performer.enqueue(body: #"{"status":"degraded"}"#)

        let status = try await TamgaClient.mocked(performer).health()

        #expect(status.status == "degraded")
        #expect(status.version == nil)
        #expect(status.uptimeSeconds == nil)
    }
}
