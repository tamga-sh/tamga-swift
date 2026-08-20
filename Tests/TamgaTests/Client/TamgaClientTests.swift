import Foundation
import Testing

@testable import Tamga

@Suite("TamgaClient")
struct TamgaClientTests {
    @Test("validateByKey sends a flat key body")
    func validateByKeySendsFlatKeyBody() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        let result = try await TamgaClient.mocked(performer).validateByKey("MY-KEY")

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/actions/validate-key")
        #expect(await performer.requestBody(at: 0) == "{\"key\":\"MY-KEY\"}")
        #expect(result.meta.code == .valid)
        #expect(result.license.status == "ACTIVE")
        #expect(result.license.machinesCount == 2)
    }

    @Test("validateById omits an empty scope entirely")
    func validateByIdOmitsAnEmptyScope() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        _ = try await TamgaClient.mocked(performer).validateById("lic-1")

        // A present `scope` key is a constraint the server evaluates, so an
        // unset scope must not be sent as null.
        let body = await performer.requestBody(at: 0)
        #expect(!body.contains("scope"))
        #expect(body.contains("skip_touch"))
    }

    @Test("validateById sends only the populated scope fields")
    func validateByIdSendsOnlyPopulatedScopeFields() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        _ = try await TamgaClient.mocked(performer).validateById(
            "lic-1",
            options: ValidateOptions(scope: Scope(product: "prod-1", user: "user-9"),
                                     skipTouch: true))

        let body = await performer.requestBody(at: 0)
        #expect(body.contains("\"product\":\"prod-1\""))
        #expect(body.contains("\"user\":\"user-9\""))
        #expect(!body.contains("policy"))
        #expect(!body.contains("checksum"))
    }

    @Test("quickValidate decodes a flat body with no envelope")
    func quickValidateDecodesFlatBody() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"ts":"2026-08-20T10:00:00Z","valid":false,"detail":"expired","code":"EXPIRED"}
        """)

        let meta = try await TamgaClient.mocked(performer).quickValidate("lic-1")

        #expect(await performer.request(at: 0)?.httpMethod == "GET")
        #expect(meta.valid == false)
        #expect(meta.code == .expired)
        #expect(meta.detail == "expired")
        #expect(meta.ts != nil)
    }

    @Test("an unrecognized validation code decodes rather than failing")
    func unrecognizedValidationCodeDecodes() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"ts":"2026-08-20T10:00:00Z","valid":false,"detail":"d","code":"INVENTED_LATER"}
        """)

        let meta = try await TamgaClient.mocked(performer).quickValidate("lic-1")

        #expect(meta.code == .unknown("INVENTED_LATER"))
        #expect(meta.code.isReachable == false)
    }

    @Test("createMachine sends an enveloped body with the license relationship")
    func createMachineSendsEnvelopedBody() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)

        let machine = try await TamgaClient.mocked(performer).createMachine(
            CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1",
                                 hostname: "box", cores: 4))

        let body = await performer.requestBody(at: 0)
        #expect(body.contains("\"type\":\"machines\""))
        #expect(body.contains("relationships"))
        #expect(body.contains("\"id\":\"lic-1\""))
        #expect(body.contains("\"metadata\":{}"))
        #expect(machine.heartbeatStatus == .alive)
        #expect(machine.cores == 4)
        #expect(machine.memory == 8_589_934_592)
        #expect(machine.hostname == "box")
    }

    @Test("createComponent sends a flat body")
    func createComponentSendsFlatBody() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"comp-1","type":"components","attributes":{"fingerprint":"cfp",\
        "name":"gpu","machine_id":"mach-1"}}}
        """)

        let component = try await TamgaClient.mocked(performer).createComponent(
            CreateComponentOptions(machineId: "mach-1", fingerprint: "cfp", name: "gpu"))

        // Deliberately NOT enveloped, unlike createMachine. The asymmetry is
        // real server behaviour.
        let body = await performer.requestBody(at: 0)
        #expect(!body.contains("\"data\""))
        #expect(body.contains("\"machine_id\":\"mach-1\""))
        #expect(component.name == "gpu")
        #expect(component.machineId == "mach-1")
    }

    @Test("createProcess keeps the pid as a string")
    func createProcessKeepsPidAsString() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"proc-1","type":"processes","attributes":{"pid":"4242",\
        "machine_id":"mach-1"}}}
        """)

        let process = try await TamgaClient.mocked(performer).createProcess(
            CreateProcessOptions(machineId: "mach-1", pid: "4242"))

        // The server types pid as a string. Sending 4242 unquoted would be a
        // different wire type.
        #expect(await performer.requestBody(at: 0).contains("\"pid\":\"4242\""))
        #expect(process.pid == "4242")
    }

    @Test("heartbeat pings hit their own actions")
    func heartbeatPingsHitTheirOwnActions() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        let client = TamgaClient.mocked(performer)

        _ = try await client.pingHeartbeat(machineId: "mach-1")
        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/machines/mach-1/actions/ping-heartbeat")

        _ = try await client.resetHeartbeat(machineId: "mach-1")
        #expect(await performer.request(at: 1)?.url?.path
            == "/v1/accounts/acct-123/machines/mach-1/actions/reset-heartbeat")
    }

    @Test("generateOfflineProof returns the proof from meta")
    func generateOfflineProofReturnsProofFromMeta() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"mach-1","type":"machines","attributes":{}},"meta":{"proof":"v1x0.abc"}}
        """)

        let result = try await TamgaClient.mocked(performer).generateOfflineProof(
            machineId: "mach-1", dataset: ["cores": .int(4)])

        #expect(await performer.requestBody(at: 0) == "{\"meta\":{\"dataset\":{\"cores\":4}}}")
        #expect(result.proof == "v1x0.abc")
        #expect(result.machine.id == "mach-1")
    }

    @Test("activateMachine returns the machine when validation passes")
    func activateMachineReturnsMachineWhenValidationPasses() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        let result = try await TamgaClient.mocked(performer).activateMachine(
            CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))

        #expect(result.machine.id == "mach-1")
        #expect(result.meta.code == .valid)
        #expect(await performer.requestCount == 2)
    }

    @Test("activateMachine rolls the machine back when over a limit")
    func activateMachineRollsBackWhenOverALimit() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        await performer.enqueue(body: Fixtures.licenseWithMeta(code: "TOO_MANY_MACHINES",
                                                               valid: false))
        await performer.enqueue(status: 204)
        let client = TamgaClient.mocked(performer)

        await #expect(throws: TamgaError.self) {
            _ = try await client.activateMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
        }

        // Creation enforces no limit, so without this delete the rejected
        // activation would leave a row behind that still consumes a seat.
        let rollback = await performer.request(at: 2)
        #expect(rollback?.httpMethod == "DELETE")
        #expect(rollback?.url?.path == "/v1/accounts/acct-123/machines/mach-1")
    }

    @Test("activateMachine reports which limit was exceeded")
    func activateMachineReportsWhichLimitWasExceeded() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        await performer.enqueue(body: Fixtures.licenseWithMeta(code: "TOO_MANY_CORES",
                                                               valid: false))
        await performer.enqueue(status: 204)

        do {
            _ = try await TamgaClient.mocked(performer).activateMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
            Issue.record("expected activation to fail")
        } catch let error as TamgaError {
            guard case .machineOverLimit(let meta) = error else {
                Issue.record("expected .machineOverLimit, got \(error)")
                return
            }
            #expect(meta.code == .tooManyCores)
        }
    }

    @Test("activateMachine keeps the machine when validation itself fails")
    func activateMachineKeepsMachineWhenValidationFails() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.machine)
        await performer.enqueue(status: 500, body: "{\"errors\":[{\"code\":\"INTERNAL_SERVER_ERROR\"}]}")
        let client = TamgaClient.mocked(performer)

        do {
            _ = try await client.activateMachine(
                CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1"))
            Issue.record("expected activation to fail")
        } catch let error as TamgaError {
            guard case .activationValidationFailed(let machine, _) = error else {
                Issue.record("expected .activationValidationFailed, got \(error)")
                return
            }
            // The machine is handed back so the caller can retry validation or
            // delete it. A transient failure is not a verdict about the
            // license, and deleting on one would destroy a seat for no reason.
            #expect(machine.id == "mach-1")
        }

        // Exactly two calls: the create and the failed validate. No DELETE.
        // This is tamga-go's behaviour; tamga-java rolls back only because
        // throwing leaves it no way to return the machine.
        #expect(await performer.requestCount == 2)
        #expect(await performer.request(at: 1)?.httpMethod != "DELETE")
    }

    @Test("checkOutLicense requests the raw certificate over GET")
    func checkOutLicenseRequestsRawCertificateOverGet() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: "-----BEGIN LICENSE FILE-----\nabc\n-----END LICENSE FILE-----")

        let pem = try await TamgaClient.mocked(performer).checkOutLicense(
            "lic-1", options: CheckOutOptions(ttl: 3600))

        let request = await performer.request(at: 0)
        #expect(request?.httpMethod == "GET")
        #expect(request?.url?.query?.contains("ttl=3600") == true)
        #expect(request?.url?.query?.contains("encrypt=false") == true)
        #expect(pem.hasPrefix("-----BEGIN LICENSE FILE-----"))
    }

    @Test("checkOutMachine can use the enveloped POST variant")
    func checkOutMachineCanUseEnvelopedPostVariant() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: """
        {"data":{"id":"mf-1","type":"machine-files","attributes":{\
        "certificate":"-----BEGIN MACHINE FILE-----","algorithm":"aes-256-gcm+ed25519"}}}
        """)

        let pem = try await TamgaClient.mocked(performer).checkOutMachine(
            "mach-1", options: CheckOutOptions(encrypt: true, usePost: true))

        let request = await performer.request(at: 0)
        #expect(request?.httpMethod == "POST")
        #expect(await performer.requestBody(at: 0).contains("\"encrypt\":true"))
        #expect(pem.hasPrefix("-----BEGIN MACHINE FILE-----"))
    }

    @Test("an out-of-range checkout time-to-live is rejected before a round trip")
    func outOfRangeCheckoutTtlIsRejectedBeforeRoundTrip() async throws {
        let performer = MockPerformer()
        let client = TamgaClient.mocked(performer)

        await #expect(throws: TamgaCheckoutError.self) {
            _ = try await client.checkOutLicense("lic-1", options: CheckOutOptions(ttl: 0))
        }
        await #expect(throws: TamgaCheckoutError.self) {
            _ = try await client.checkOutLicense(
                "lic-1", options: CheckOutOptions(ttl: CheckOutOptions.maxTtlSeconds + 1))
        }
        #expect(await performer.requestCount == 0)
    }

    @Test("deleteMachine issues a delete and tolerates an empty body")
    func deleteMachineIssuesDeleteAndToleratesEmptyBody() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 204)

        try await TamgaClient.mocked(performer).deleteMachine("mach-1")

        let request = await performer.request(at: 0)
        #expect(request?.httpMethod == "DELETE")
        #expect(request?.url?.path == "/v1/accounts/acct-123/machines/mach-1")
    }
}
