import Foundation
import Testing

@testable import Tamga

@Suite("Rate limiting")
struct RateLimitTests {
    private func throttled() -> MockPerformer.Stub {
        MockPerformer.Stub(status: 429, headers: ["Retry-After": "0"])
    }

    @Test("a throttled validation is retried and then succeeds")
    func throttledValidationIsRetriedThenSucceeds() async throws {
        let performer = MockPerformer()
        await performer.enqueue(throttled())
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        let result = try await TamgaClient.mocked(performer).validateByKey("K")

        #expect(result.isValid)
        #expect(await performer.requestCount == 2)
    }

    @Test("machine creation is never retried")
    func machineCreationIsNeverRetried() async throws {
        // Retrying a create risks a second activation burning a second seat, so
        // the 429 must surface rather than being papered over.
        let performer = MockPerformer()
        await performer.enqueue(throttled())
        let client = TamgaClient.mocked(performer)

        await #expect(throws: TamgaError.self) {
            _ = try await client.createMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
        }
        #expect(await performer.requestCount == 1)
    }

    @Test("retrying is disabled when the budget is zero")
    func retryingIsDisabledWhenBudgetIsZero() async throws {
        let performer = MockPerformer()
        await performer.enqueue(throttled())
        let client = TamgaClient.mocked(performer, maxRetries: 0)

        await #expect(throws: TamgaError.self) {
            _ = try await client.validateByKey("K")
        }
        #expect(await performer.requestCount == 1)
    }

    @Test("the retry budget is finite")
    func retryBudgetIsFinite() async throws {
        let performer = MockPerformer()
        await performer.enqueue(throttled())
        let client = TamgaClient.mocked(performer, maxRetries: 2)

        await #expect(throws: TamgaError.self) {
            _ = try await client.validateByKey("K")
        }
        // One original attempt plus exactly two retries.
        #expect(await performer.requestCount == 3)
    }

    @Test("a retried request resends its body")
    func retriedRequestResendsItsBody() async throws {
        let performer = MockPerformer()
        await performer.enqueue(throttled())
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        _ = try await TamgaClient.mocked(performer).validateByKey("SECRET-KEY")

        #expect(await performer.requestBody(at: 1).contains("SECRET-KEY"))
    }

    @Test("every GET is retryable")
    func everyGetIsRetryable() {
        #expect(Transport.isRetryable(method: "GET", path: "/licenses/lic-1/entitlements"))
        #expect(Transport.isRetryable(method: "GET", path: "/anything/at/all"))
    }

    @Test("only the five safe post actions are retryable")
    func onlyTheFiveSafePostActionsAreRetryable() {
        #expect(Transport.isRetryable(method: "POST", path: "/licenses/actions/validate-key"))
        #expect(Transport.isRetryable(method: "POST", path: "/licenses/lic-1/actions/validate"))
        #expect(Transport.isRetryable(method: "POST", path: "/licenses/lic-1/actions/check-in"))
        #expect(Transport.isRetryable(method: "POST", path: "/licenses/lic-1/actions/check-out"))
        #expect(Transport.isRetryable(method: "POST", path: "/processes/p-1/actions/ping"))

        #expect(!Transport.isRetryable(method: "POST", path: "/machines"))
        #expect(!Transport.isRetryable(method: "POST", path: "/components"))
        #expect(!Transport.isRetryable(method: "POST", path: "/processes"))
        #expect(!Transport.isRetryable(method: "DELETE", path: "/machines/m-1"))
    }

    @Test("heartbeat pings are not treated as the retryable ping action")
    func heartbeatPingsAreNotTheRetryablePingAction() {
        // Suffix matching, not substring: `ping-heartbeat` must not be mistaken
        // for `/actions/ping`.
        #expect(!Transport.isRetryable(method: "POST",
                                       path: "/machines/m-1/actions/ping-heartbeat"))
        #expect(!Transport.isRetryable(method: "POST",
                                       path: "/machines/m-1/actions/reset-heartbeat"))
    }

    @Test("an absurd retry-after is capped")
    func absurdRetryAfterIsCapped() {
        let delay = Transport.retryDelayMilliseconds(attempt: 0, retryAfterSeconds: 100_000,
                                                     jitterMilliseconds: 0)

        #expect(delay == UInt64(Transport.maxRetryAfterSeconds) * 1000)
    }

    @Test("a server-supplied retry-after is honoured")
    func serverSuppliedRetryAfterIsHonoured() {
        #expect(Transport.retryDelayMilliseconds(attempt: 0, retryAfterSeconds: 5,
                                                 jitterMilliseconds: 0) == 5_000)
    }

    @Test("backoff grows and then plateaus, carrying jitter")
    func backoffGrowsThenPlateausCarryingJitter() {
        #expect(Transport.retryDelayMilliseconds(attempt: 0, retryAfterSeconds: nil,
                                                 jitterMilliseconds: 0) == 1_000)
        #expect(Transport.retryDelayMilliseconds(attempt: 1, retryAfterSeconds: nil,
                                                 jitterMilliseconds: 0) == 2_000)
        #expect(Transport.retryDelayMilliseconds(attempt: 2, retryAfterSeconds: nil,
                                                 jitterMilliseconds: 0) == 4_000)
        // Plateaus rather than growing without bound.
        #expect(Transport.retryDelayMilliseconds(attempt: 50, retryAfterSeconds: nil,
                                                 jitterMilliseconds: 0) == 32_000)
        // Jitter is added, so a fleet does not resynchronize onto one schedule.
        #expect(Transport.retryDelayMilliseconds(attempt: 0, retryAfterSeconds: nil,
                                                 jitterMilliseconds: 250) == 1_250)
    }

    @Test("an unusable retry-after falls back to local backoff")
    func unusableRetryAfterFallsBackToLocalBackoff() {
        // The HTTP-date form is deliberately not parsed: misreading a date as a
        // duration would be far worse than backing off locally.
        #expect(Transport.parseRetryAfterSeconds("Wed, 21 Oct 2026 07:28:00 GMT") == nil)
        #expect(Transport.parseRetryAfterSeconds("-5") == nil)
        #expect(Transport.parseRetryAfterSeconds("") == nil)
        #expect(Transport.parseRetryAfterSeconds(nil) == nil)
        #expect(Transport.parseRetryAfterSeconds(" 7 ") == 7)
    }
}
