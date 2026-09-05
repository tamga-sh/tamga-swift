import Foundation
import Testing

@testable import Tamga

/// Regression cover for the server-contract drift found across the SDK fleet.
///
/// Every fixture here uses the server's real wire shape, including the detail
/// that trips hand-written fixtures: JSON:API renders `status` as a **string**
/// (`"422"`), not a number.
@Suite("Server contract alignment")
struct ServerContractTests {
    /// A JSON:API error document exactly as the server renders one.
    private static func errorBody(
        status: String,
        code: String,
        detail: String,
        pointer: String? = nil
    ) -> String {
        let source = pointer.map { ",\"source\":{\"pointer\":\"\($0)\"}" } ?? ""
        return """
        {"errors":[{"id":"err-1","status":"\(status)","code":"\(code)",\
        "title":"Unprocessable","detail":"\(detail)"\(source)}]}
        """
    }

    // MARK: - (b) error codes surface with the server's own code intact

    @Test("a create-time MACHINE_LIMIT_EXCEEDED keeps the server's code and status")
    func machineLimitExceededKeepsServerCode() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 422, body: Self.errorBody(
            status: "422",
            code: TamgaAPIErrorCode.machineLimitExceeded,
            detail: "machine count has reached its limit",
            pointer: "/data/relationships/license"))
        let client = TamgaClient.mocked(performer)

        do {
            _ = try await client.createMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
            Issue.record("expected the create to fail")
        } catch let error as TamgaError {
            guard case .api(let apiError) = error else {
                Issue.record("expected .api, got \(error)")
                return
            }
            // The code is what callers match on, and it must survive verbatim.
            #expect(apiError.code == "MACHINE_LIMIT_EXCEEDED")
            #expect(apiError.httpStatus == 422)
            #expect(apiError.pointer == "/data/relationships/license")
            #expect(error.apiCode == "MACHINE_LIMIT_EXCEEDED")
            // ...and it normalizes onto the validate-time vocabulary.
            #expect(error.limitValidationCode == .tooManyMachines)
            #expect(error.isPolicyLimitExceeded)
        }
    }

    @Test("every create-time limit code maps to its validation equivalent")
    func everyLimitCodeMapsToItsValidationEquivalent() {
        #expect(TamgaAPIErrorCode.limitValidationCode(for: "MACHINE_LIMIT_EXCEEDED")
            == .tooManyMachines)
        #expect(TamgaAPIErrorCode.limitValidationCode(for: "CORE_LIMIT_EXCEEDED") == .tooManyCores)
        #expect(TamgaAPIErrorCode.limitValidationCode(for: "MEMORY_LIMIT_EXCEEDED")
            == .tooMuchMemory)
        #expect(TamgaAPIErrorCode.limitValidationCode(for: "DISK_LIMIT_EXCEEDED") == .tooMuchDisk)
        #expect(TamgaAPIErrorCode.limitValidationCode(for: "TOO_MANY_PROCESSES")
            == .tooManyProcesses)

        // Not a limit: a re-activation, which must not be rewritten into one.
        #expect(TamgaAPIErrorCode.limitValidationCode(for: "FINGERPRINT_TAKEN") == nil)
        #expect(TamgaAPIErrorCode.limitValidationCode(for: "NOT_FOUND") == nil)
    }

    @Test("a 401 LICENSE_NOT_ALLOWED is reported as a policy precondition")
    func licenseNotAllowedIsReportedAsPolicyPrecondition() async throws {
        // The policy's authentication_strategy defaults to TOKEN, so license-key
        // auth is refused until a policy opts into LICENSE or MIXED. Retrying
        // and re-prompting for a key both accomplish nothing.
        let performer = MockPerformer()
        await performer.enqueue(status: 401, body: Self.errorBody(
            status: "401",
            code: TamgaAPIErrorCode.licenseNotAllowed,
            detail: "license authentication is not allowed for this policy"))
        let client = TamgaClient.mocked(performer, auth: .licenseKey("lic-key"))

        do {
            _ = try await client.validateByKey("lic-key")
            Issue.record("expected authentication to fail")
        } catch let error as TamgaError {
            #expect(error.apiCode == "LICENSE_NOT_ALLOWED")
            #expect(error.httpStatus == 401)
            #expect(error.isLicenseAuthenticationRejected)
            // Not a limit, so activation must not mistake it for one.
            #expect(error.limitValidationCode == nil)
            #expect(error.overLimitMeta == nil)
        }
    }

    @Test("suspended and revoked-expiry licences are also auth rejections")
    func suspendedAndExpiredAreAuthRejections() async throws {
        for code in [TamgaAPIErrorCode.licenseSuspended, TamgaAPIErrorCode.licenseExpired] {
            let performer = MockPerformer()
            await performer.enqueue(status: 401, body: Self.errorBody(
                status: "401", code: code, detail: "refused"))

            do {
                _ = try await TamgaClient.mocked(performer).validateByKey("K")
                Issue.record("expected authentication to fail for \(code)")
            } catch let error as TamgaError {
                #expect(error.apiCode == code)
                #expect(error.isLicenseAuthenticationRejected)
            }
        }
    }

    // MARK: - (c) activation handles both limit checks

    @Test("activateMachine turns a create-time 422 into machineOverLimit without a rollback")
    func activateMachineHandlesCreateTimeLimitWithoutRollback() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 422, body: Self.errorBody(
            status: "422",
            code: TamgaAPIErrorCode.machineLimitExceeded,
            detail: "machine count has reached its limit"))
        let client = TamgaClient.mocked(performer)

        do {
            _ = try await client.activateMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
            Issue.record("expected activation to fail")
        } catch let error as TamgaError {
            guard case .machineOverLimit(let meta) = error else {
                Issue.record("expected .machineOverLimit, got \(error)")
                return
            }
            #expect(meta.code == .tooManyMachines)
            #expect(meta.valid == false)
            #expect(meta.detail == "machine count has reached its limit")
            // No validation ran, so there is no server timestamp to report.
            #expect(meta.ts == nil)
        }

        // Exactly one call. The server refused before writing a row, so there is
        // no seat to reclaim and a DELETE would target an id never issued.
        #expect(await performer.requestCount == 1)
        #expect(await performer.request(at: 0)?.httpMethod == "POST")
    }

    @Test("a create-time core limit maps to TOO_MANY_CORES")
    func createTimeCoreLimitMapsToTooManyCores() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 422, body: Self.errorBody(
            status: "422", code: TamgaAPIErrorCode.coreLimitExceeded, detail: "too many cores"))

        do {
            _ = try await TamgaClient.mocked(performer).activateMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1", cores: 64))
            Issue.record("expected activation to fail")
        } catch let error as TamgaError {
            guard case .machineOverLimit(let meta) = error else {
                Issue.record("expected .machineOverLimit, got \(error)")
                return
            }
            #expect(meta.code == .tooManyCores)
        }
    }

    @Test("activateMachine still rolls back when overage lets the create through")
    func activateMachineStillRollsBackUnderOverage() async throws {
        // Under ALLOW_ACCESS / ALLOW_1_25X_OVERAGE the create-time limit check
        // passes and the limit only surfaces at validate time. That path must
        // keep deleting the row it created, or the rejected activation leaves a
        // machine behind still consuming a seat.
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        await performer.enqueue(body: Fixtures.licenseWithMeta(code: "TOO_MANY_MACHINES",
                                                               valid: false))
        await performer.enqueue(status: 204)
        let client = TamgaClient.mocked(performer)

        do {
            _ = try await client.activateMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
            Issue.record("expected activation to fail")
        } catch let error as TamgaError {
            guard case .machineOverLimit(let meta) = error else {
                Issue.record("expected .machineOverLimit, got \(error)")
                return
            }
            #expect(meta.code == .tooManyMachines)
            // The validate-time path does carry the server's timestamp, unlike
            // the create-time one.
            #expect(meta.ts != nil)
        }

        #expect(await performer.requestCount == 3)
        let rollback = await performer.request(at: 2)
        #expect(rollback?.httpMethod == "DELETE")
        #expect(rollback?.url?.path == "/v1/accounts/acct-123/machines/mach-1")
    }

    @Test("a non-limit create failure is rethrown untouched")
    func nonLimitCreateFailureIsRethrownUntouched() async throws {
        // A re-activation is a 409, not a limit. Rewriting it into
        // `.machineOverLimit` would tell the caller to free a seat when what
        // they actually need is to recover the existing machine.
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: Self.errorBody(
            status: "409",
            code: TamgaAPIErrorCode.fingerprintTaken,
            detail: "fingerprint is already taken"))

        do {
            _ = try await TamgaClient.mocked(performer).activateMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
            Issue.record("expected activation to fail")
        } catch let error as TamgaError {
            #expect(error.apiCode == "FINGERPRINT_TAKEN")
            #expect(error.httpStatus == 409)
        }
        #expect(await performer.requestCount == 1)
    }

    // MARK: - M7: the two scope fields that sink a whole validate call

    @Test("version and checksum are never sent on a validate request")
    func versionAndChecksumAreNeverSent() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        _ = try await TamgaClient.mocked(performer).validateById(
            "lic-1",
            options: ValidateOptions(scope: Scope(product: "prod-1",
                                                  version: "1.2.3",
                                                  checksum: "deadbeef")))

        // Present on the request, either one draws 422 SCOPE_NOT_SUPPORTED and
        // the whole call fails -- no verdict at all, rather than an ignored
        // field. Dropping them degrades to a working validate.
        let body = await performer.requestBody(at: 0)
        #expect(body.contains("\"product\":\"prod-1\""))
        #expect(!body.contains("1.2.3"))
        #expect(!body.contains("deadbeef"))
    }

    @Test("a scope carrying only the dropped fields is omitted entirely")
    func scopeOfOnlyDroppedFieldsIsOmitted() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        _ = try await TamgaClient.mocked(performer).validateById(
            "lic-1", options: ValidateOptions(scope: Scope(version: "1.2.3")))

        // A bare `"scope":{}` is not what the caller asked for either.
        #expect(!(await performer.requestBody(at: 0)).contains("scope"))
    }

    @Test("the enforced scope fields are still sent")
    func enforcedScopeFieldsAreStillSent() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        _ = try await TamgaClient.mocked(performer).validateById(
            "lic-1",
            options: ValidateOptions(scope: Scope(fingerprint: "fp-1",
                                                  entitlements: ["PRO", "BETA"])))

        // Both were parsed-then-ignored once and are genuinely enforced now.
        let body = await performer.requestBody(at: 0)
        #expect(body.contains("\"fingerprint\":\"fp-1\""))
        #expect(body.contains("PRO"))
        #expect(body.contains("BETA"))
    }

    // MARK: - M8: reachability

    @Test("the two newly enforced scope verdicts are reachable")
    func newlyEnforcedScopeVerdictsAreReachable() {
        #expect(ValidationCode.entitlementsMissing.isReachable)
        #expect(ValidationCode.fingerprintScopeMismatch.isReachable)
        // These two are not: sending the field now fails the call instead.
        #expect(!ValidationCode.versionScopeMismatch.isReachable)
        #expect(!ValidationCode.checksumScopeMismatch.isReachable)
    }

    @Test("the heartbeat verdicts and TOO_MANY_USERS are reachable since the API patch")
    func heartbeatAndUsersVerdictsAreReachable() {
        #expect(ValidationCode.heartbeatNotStarted.isReachable)
        #expect(ValidationCode.heartbeatDead.isReachable)
        #expect(ValidationCode.tooManyUsers.isReachable)
        for code in [ValidationCode.notFound, .banned, .componentsScopeMismatch,
                     .checksumScopeMismatch, .versionScopeMismatch] {
            #expect(!code.isReachable)
        }
        // None of the three joins the rollback set.
        #expect(!ValidationCode.heartbeatDead.isOverLimit)
        #expect(!ValidationCode.heartbeatNotStarted.isOverLimit)
        #expect(!ValidationCode.tooManyUsers.isOverLimit)
    }

    @Test("an ENTITLEMENTS_MISSING verdict decodes as a known code")
    func entitlementsMissingDecodesAsKnownCode() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.licenseWithMeta(code: "ENTITLEMENTS_MISSING",
                                                               valid: false))

        let result = try await TamgaClient.mocked(performer).validateById(
            "lic-1", options: ValidateOptions(scope: Scope(entitlements: ["PRO"])))

        #expect(result.meta.code == .entitlementsMissing)
        #expect(result.meta.code.wireValue == "ENTITLEMENTS_MISSING")
        #expect(result.isValid == false)
        // Not a limit, so it must not trigger activation's rollback.
        #expect(!result.meta.code.isOverLimit)
    }

    // MARK: - M37: strategy values

    @Test("both late-added strategy values are modeled")
    func lateAddedStrategyValuesAreModeled() {
        #expect(ExpirationStrategy.allValues.contains("REVOKE_ACCESS"))
        #expect(AuthenticationStrategy.allValues.contains("NONE"))
    }

    @Test("license-key auth is permitted only under LICENSE or MIXED")
    func licenseKeyAuthIsPermittedOnlyUnderLicenseOrMixed() {
        #expect(AuthenticationStrategy.permitsLicenseKey("LICENSE"))
        #expect(AuthenticationStrategy.permitsLicenseKey("MIXED"))
        // The default, and the one whose name suggests otherwise.
        #expect(!AuthenticationStrategy.permitsLicenseKey("TOKEN"))
        #expect(!AuthenticationStrategy.permitsLicenseKey("NONE"))
        #expect(!AuthenticationStrategy.permitsLicenseKey(nil))
    }

    // MARK: - M34: the client must not race the server's own timeout

    @Test("the default timeout outlives the server's 30-second cap")
    func defaultTimeoutOutlivesServerCap() {
        // Equal deadlines race, and the local one usually wins -- discarding the
        // server's 504 and the x-request-id that comes with it.
        #expect(TamgaClient.defaultTimeout > 30)
    }
}
