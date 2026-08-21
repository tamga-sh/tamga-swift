import Foundation
import Testing

@testable import Tamga

@Suite("Licence and policy reads")
struct ResourceReadTests {
    @Test("getLicense reads the licence resource")
    func getLicenseReadsTheResource() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Fixtures.license)

        let license = try await TamgaClient.mocked(performer).getLicense("lic-1")

        #expect(await performer.request(at: 0)?.url?.path == "/v1/accounts/acct-123/licenses/lic-1")
        #expect(await performer.request(at: 0)?.httpMethod == "GET")
        #expect(license.key == "K")
    }

    @Test("getPolicy reads the policy resource")
    func getPolicyReadsTheResource() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.policy)

        let policy = try await TamgaClient.mocked(performer).getPolicy("pol-1")

        #expect(await performer.request(at: 0)?.url?.path == "/v1/accounts/acct-123/policies/pol-1")
        #expect(policy.heartbeatDuration == 90)
        #expect(policy.requireHeartbeat)
        // The real-world bogus default still normalizes to the permissive case.
        #expect(policy.overageStrategy == .noOverage)
        #expect(policy.overageStrategyRaw == "DENY_ACCESS")
        #expect(policy.checkInInterval == .day)
    }

    @Test("getLicensePolicy reads the policy through the licence")
    func getLicensePolicyReadsThroughTheLicence() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.policy)

        let policy = try await TamgaClient.mocked(performer).getLicensePolicy("lic-1")

        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/licenses/lic-1/policy")
        #expect(policy.id == "pol-1")
    }
}

@Suite("Machine reads")
struct MachineReadTests {
    @Test("getMachine can report DEAD, which no ping response ever can")
    func getMachineReportsDead() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.machine(status: "DEAD"))

        let machine = try await TamgaClient.mocked(performer).getMachine("mach-1")

        #expect(await performer.request(at: 0)?.url?.path == "/v1/accounts/acct-123/machines/mach-1")
        // This is the whole point of the read route: the status is derived from
        // a stored timestamp rather than one the same request just wrote.
        #expect(machine.heartbeatStatus == .dead)
        #expect(machine.nextHeartbeatAt != nil)
    }

    @Test("listMachines sends the offset spelling and reads meta.page")
    func listMachinesIsOffsetPaginated() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.machineList(["a", "b"], total: 250))

        let page = try await TamgaClient.mocked(performer).listMachines(
            options: ListMachinesOptions(pageNumber: 2, pageSize: 50))

        let query = await performer.request(at: 0)?.url?.query ?? ""
        #expect(query.contains("page%5Bsize%5D=50"))
        #expect(query.contains("page%5Bnumber%5D=2"))
        // Not the keyset cursor the rest of the domain uses.
        #expect(!query.contains("after"))
        #expect(page.pageInfo?.total == 250)
        #expect(page.pageInfo?.totalPages == 1)
        #expect(page.pageInfo?.hasNextPage == false)
        #expect(page.pageInfo?.nextPageNumber == nil)
        #expect(page.items.count == 2)
    }

    @Test("a page short of the last one reports the next page number")
    func pageInfoAdvances() {
        let info = PageInfo(number: 1, size: 100, total: 250, totalPages: 3)

        #expect(info.hasNextPage)
        #expect(info.nextPageNumber == 2)
    }

    @Test("a response with no meta.page reports nil rather than an empty page")
    func missingPageMetaIsNil() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.machineList(["a"], withMeta: false))

        let page = try await TamgaClient.mocked(performer).listMachines()

        // "Unknown" and "one page of zero" are different answers.
        #expect(page.pageInfo == nil)
        #expect(page.items.count == 1)
    }

    @Test("filters are comma-joined into one value, never repeated keys")
    func filtersAreCommaJoined() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.machineList([]))

        _ = try await TamgaClient.mocked(performer).listMachines(
            options: ListMachinesOptions(licenseIds: ["lic-1", "lic-2"],
                                         ownerIds: ["usr-1"],
                                         groupIds: ["grp-1"],
                                         platforms: ["darwin"],
                                         query: "fp-1",
                                         sort: MachineSortField.lastHeartbeatAt,
                                         descending: true))

        let query = await performer.request(at: 0)?.url?.query ?? ""
        // Repeated keys silently collapse to the last value server-side, which
        // would drop half of a multi-value filter.
        #expect(query.contains("filter%5Blicense%5D=lic-1,lic-2"))
        #expect(query.contains("filter%5Bowner%5D=usr-1"))
        #expect(query.contains("filter%5Bgroup%5D=grp-1"))
        #expect(query.contains("filter%5Bplatform%5D=darwin"))
        #expect(query.contains("filter%5Bq%5D=fp-1"))
        #expect(query.contains("sort=last_heartbeat_at"))
        #expect(query.contains("order=desc"))
    }

    @Test("an unset sort sends neither sort nor order")
    func unsetSortIsOmitted() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.machineList([]))

        _ = try await TamgaClient.mocked(performer).listMachines()

        let query = await performer.request(at: 0)?.url?.query ?? ""
        #expect(!query.contains("sort="))
        #expect(!query.contains("order="))
        #expect(!query.contains("filter"))
        #expect(query.contains("page%5Bsize%5D=100"))
    }

    @Test("listMachineProcesses is keyset, unlike the machine collection")
    func listMachineProcessesIsKeyset() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.processList(3))

        let page = try await TamgaClient.mocked(performer).listMachineProcesses(
            machineId: "mach-1", options: ListOptions(after: "proc-9", limit: 3))

        let url = await performer.request(at: 0)?.url
        #expect(url?.path == "/v1/accounts/acct-123/machines/mach-1/processes")
        #expect(url?.query?.contains("page%5Bafter%5D=proc-9") == true)
        #expect(url?.query?.contains("limit=3") == true)
        // A full page yields a synthesized cursor -- this route reports none.
        #expect(page.nextCursor == "proc-2")
        #expect(page.items.first?.pid == "1000")
    }

    @Test("a short process page ends the cursor")
    func shortProcessPageEndsTheCursor() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.processList(2))

        let page = try await TamgaClient.mocked(performer).listMachineProcesses(
            machineId: "mach-1", options: ListOptions(limit: 5))

        #expect(page.nextCursor == nil)
    }
}

@Suite("Machine update")
struct MachineUpdateTests {
    @Test("updateMachine sends an enveloped body carrying only the set fields")
    func updateSendsOnlySetFields() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: SurfaceFixtures.machine())

        _ = try await TamgaClient.mocked(performer).updateMachine(
            "mach-1", options: UpdateMachineOptions(hostname: "box-2", cores: 8))

        #expect(await performer.request(at: 0)?.httpMethod == "PATCH")
        let body = await performer.requestBody(at: 0)
        #expect(body.contains("\"type\":\"machines\""))
        #expect(body.contains("\"hostname\":\"box-2\""))
        #expect(body.contains("\"cores\":8"))
        // Omission is how "leave unchanged" is spelled; an explicit null means
        // the same thing server-side but claims an intent the caller never had.
        #expect(!body.contains("\"name\""))
        #expect(!body.contains("\"metadata\""))
    }

    @Test("an update with nothing set fails before the request")
    func emptyUpdateFailsLocally() async throws {
        let performer = MockPerformer()

        await #expect(throws: TamgaError.self) {
            _ = try await TamgaClient.mocked(performer).updateMachine(
                "mach-1", options: UpdateMachineOptions())
        }
        // A no-op PATCH would come back 200 and look like a successful update.
        #expect(await performer.requestCount == 0)
    }
}
