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

    @Test("health still sends the configured credential")
    func healthSendsCredentials() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.health)

        _ = try await TamgaClient.mocked(performer, auth: .bearer("tok-1")).health()

        #expect(await performer.request(at: 0)?
            .value(forHTTPHeaderField: "Authorization") == "Bearer tok-1")
        // Not application/vnd.api+json: the body is a plain object.
        #expect(await performer.request(at: 0)?
            .value(forHTTPHeaderField: "Accept") == "application/json")
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
