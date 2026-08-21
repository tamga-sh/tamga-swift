import Foundation
import Testing

@testable import Tamga

@Suite("Process deletion")
struct ProcessDeletionTests {
    @Test("deleteProcess issues a DELETE against the process")
    func deleteProcessIssuesADelete() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 204, body: "")

        try await TamgaClient.mocked(performer).deleteProcess("proc-1")

        #expect(await performer.request(at: 0)?.httpMethod == "DELETE")
        #expect(await performer.request(at: 0)?.url?.path
            == "/v1/accounts/acct-123/processes/proc-1")
    }

    @Test("stopAndDelete stops the scheduler and deletes the row")
    func stopAndDeleteStopsThenDeletes() async throws {
        let performer = MockPerformer()
        await performer.enqueue(status: 204, body: "")
        let scheduler = ProcessHeartbeatScheduler(
            client: TamgaClient.mocked(performer), processId: "proc-1")

        await scheduler.start()
        #expect(await scheduler.isRunning)
        try await scheduler.stopAndDelete()

        #expect(await scheduler.isRunning == false)
        #expect(await performer.request(at: 0)?.httpMethod == "DELETE")
    }
}
