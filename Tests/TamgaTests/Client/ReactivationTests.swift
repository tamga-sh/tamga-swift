import Foundation
import Testing

@testable import Tamga

@Suite("Idempotent re-activation")
struct ReactivationTests {
    private static let options = CreateMachineOptions(fingerprint: "fp-1", licenseId: "lic-1")

    @Test("a first activation goes straight through")
    func firstActivationIsUnchanged() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.machine())
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        let result = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)

        #expect(await performer.requestCount == 2)
        #expect(result.machine.id == "mach-1")
        #expect(result.meta.code == .valid)
    }

    @Test("a 409 is resolved into the machine that already holds the fingerprint")
    func conflictResolvesToTheExistingMachine() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.conflict())
        // The lookup is a substring search across three columns, so it can
        // return near-misses; only the exact fingerprint counts.
        await performer.enqueue(body: SurfaceFixtures.machineList(["fp-10", "fp-1"]))
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        let result = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)

        #expect(result.machine.fingerprint == "fp-1")
        #expect(result.machine.id == "mach-1")
        let lookup = await performer.request(at: 1)?.url?.query ?? ""
        #expect(lookup.contains("filter%5Bq%5D=fp-1"))
        // Licence-scoped on purpose. All three uniqueness strategies include
        // the caller's own rows, so a genuine re-activation is always found
        // here; widening the search would only add the cross-licence case the
        // server refuses in order to stop seat-sharing.
        #expect(lookup.contains("filter%5Blicense%5D=lic-1"))
        #expect(await performer.request(at: 2)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/actions/validate")
    }

    @Test("a substring near-miss is never mistaken for the machine")
    func nearMissIsNotAdopted() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.conflict())
        // `filter[q]` is `%term%` across name/hostname/fingerprint, so a longer
        // fingerprint containing this one comes back too. Only equality counts.
        await performer.enqueue(body: SurfaceFixtures.machineList(["fp-1-extended"]))

        await #expect(throws: TamgaError.self) {
            _ = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)
        }
    }

    @Test("the original 409 is rethrown when the lookup finds no exact match")
    func unmatchedLookupRethrowsTheConflict() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.conflict())
        // Nothing on this licence carries the fingerprint, so the conflict came
        // from a wider uniqueness scope: the machine is on another licence, and
        // adopting it would be the seat-sharing the server refused.
        await performer.enqueue(body: SurfaceFixtures.machineList(["fp-10"]))

        do {
            _ = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)
            Issue.record("expected the conflict to be rethrown")
        } catch let error as TamgaError {
            // Not a synthesized 404: the server's own verdict survives.
            #expect(error.isFingerprintTaken)
            #expect(error.httpStatus == 409)
        }
        #expect(await performer.requestCount == 2)
    }

    @Test("an adopted machine is never deleted on an over-limit verdict")
    func adoptedMachineIsNotRolledBack() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.conflict())
        await performer.enqueue(body: SurfaceFixtures.machineList(["fp-1"]))
        await performer.enqueue(body: Fixtures.licenseWithMeta(code: "TOO_MANY_MACHINES",
                                                               valid: false))

        do {
            _ = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)
            Issue.record("expected machineOverLimit")
        } catch let error as TamgaError {
            guard case .machineOverLimit(let meta) = error else {
                Issue.record("expected machineOverLimit, got \(error)")
                return
            }
            #expect(meta.code == .tooManyMachines)
        }
        // Rolling back here would surrender a seat this call never created.
        let methods = await (0..<performer.requestCount).asyncMap {
            await performer.request(at: $0)?.httpMethod
        }
        #expect(!methods.contains("DELETE"))
    }

    @Test("a failed validation hands back the machine it adopted")
    func failedValidationReturnsTheAdoptedMachine() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.conflict())
        await performer.enqueue(body: SurfaceFixtures.machineList(["fp-1"]))
        await performer.enqueue(status: 500, body: """
        {"errors":[{"code":"INTERNAL_SERVER_ERROR","detail":"boom"}]}
        """)

        do {
            _ = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)
            Issue.record("expected activationValidationFailed")
        } catch let error as TamgaError {
            guard case .activationValidationFailed(let machine, _) = error else {
                Issue.record("expected activationValidationFailed, got \(error)")
                return
            }
            #expect(machine.fingerprint == "fp-1")
        }
    }

    @Test("a conflict that is not FINGERPRINT_TAKEN is not resolved")
    func otherConflictsAreRethrownWithoutALookup() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.conflict(code: "KEY_TAKEN"))

        await #expect(throws: TamgaError.self) {
            _ = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)
        }
        // No lookup: a 409 is not on its own a re-activation.
        #expect(await performer.requestCount == 1)
    }

    @Test("a same-licence 409 is resolved through the machine it names, with no search")
    func conflictWithMetaAdoptsByIdWithoutSearching() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.sameLicenseConflict(machineId: "mach-9"))
        await performer.enqueue(body: SurfaceFixtures.machine(id: "mach-9", fingerprint: "fp-1"))
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        let result = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)

        #expect(result.machine.id == "mach-9")
        #expect(result.meta.code == .valid)
        #expect(await performer.requestCount == 3)
        let read = await performer.request(at: 1)
        #expect(read?.httpMethod == "GET")
        #expect(read?.url?.path == "/v1/accounts/acct-123/machines/mach-9")
        // No paginated search: the server already said which machine it is.
        #expect(read?.url?.query == nil)
        #expect(await performer.request(at: 2)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/actions/validate")
    }

    @Test("a 409 without meta falls back to the licence-scoped search")
    func conflictWithoutMetaSearches() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.conflict())
        await performer.enqueue(body: SurfaceFixtures.machineList(["fp-1"]))
        await performer.enqueue(body: Fixtures.licenseWithMeta())

        _ = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)

        let lookup = await performer.request(at: 1)?.url
        #expect(lookup?.path == "/v1/accounts/acct-123/machines")
        #expect(lookup?.query?.contains("filter%5Blicense%5D=lic-1") == true)
    }

    @Test("a named machine that is already gone falls back to the search, then rethrows the 409")
    func namedMachineGoneFallsBackAndRethrowsTheConflict() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: SurfaceFixtures.sameLicenseConflict(machineId: "mach-9"))
        await performer.enqueue(status: 404, body: """
        {"errors":[{"status":"404","code":"NOT_FOUND","detail":"gone"}]}
        """)
        await performer.enqueue(body: SurfaceFixtures.machineList([]))

        do {
            _ = try await TamgaClient.mocked(performer).reactivateMachine(Self.options)
            Issue.record("expected the conflict to be rethrown")
        } catch let error as TamgaError {
            #expect(error.isFingerprintTaken)
            #expect(!error.isNotFound)
        }
        #expect(await performer.requestCount == 3)
    }
}
