import Foundation
import Testing

@testable import Tamga

@Suite("Error mapping")
struct ErrorMappingTests {
    private func apiError(from performer: MockPerformer) async -> TamgaError.APIError? {
        let client = TamgaClient.mocked(performer)
        do {
            _ = try await client.checkIn("lic-1")
            return nil
        } catch let error as TamgaError {
            if case .api(let apiError) = error { return apiError }
            return nil
        } catch {
            return nil
        }
    }

    @Test("an error response becomes a typed api error")
    func errorResponseBecomesTypedApiError() async {
        let performer = MockPerformer()
        await performer.enqueue(status: 404,
                                body: """
                                {"errors":[{"code":"NOT_FOUND","detail":"no such license",\
                                "title":"Not Found","id":"e-1","source":{"pointer":"/data/id"}}]}
                                """,
                                headers: ["X-Request-Id": "req-9", "Tamga-Edition": "EE"])

        let error = await apiError(from: performer)

        #expect(error?.code == "NOT_FOUND")
        #expect(error?.httpStatus == 404)
        #expect(error?.detail == "no such license")
        #expect(error?.title == "Not Found")
        #expect(error?.id == "e-1")
        #expect(error?.pointer == "/data/id")
        #expect(error?.responseMetadata.requestId == "req-9")
        #expect(error?.responseMetadata.tamgaEdition == "EE")
    }

    @Test("a non-json:api error body degrades to an unknown code")
    func nonJsonApiErrorBodyDegradesToUnknownCode() async {
        // Error bodies arrive from the network and are untrusted. Failing to
        // parse one must not mask the HTTP status, which is the reliable part.
        let performer = MockPerformer()
        await performer.enqueue(status: 502, body: "<html>gateway blew up</html>")

        let error = await apiError(from: performer)

        #expect(error?.code == TamgaError.APIError.unknownCode)
        #expect(error?.httpStatus == 502)
    }

    @Test("an empty errors array degrades to an unknown code")
    func emptyErrorsArrayDegradesToUnknownCode() async {
        let performer = MockPerformer()
        await performer.enqueue(status: 500, body: "{\"errors\":[]}")

        #expect(await apiError(from: performer)?.code == TamgaError.APIError.unknownCode)
    }

    @Test("an error with no code is treated as unknown")
    func errorWithNoCodeIsTreatedAsUnknown() async {
        let performer = MockPerformer()
        await performer.enqueue(status: 422,
                                body: "{\"errors\":[{\"detail\":\"something went wrong\"}]}")

        let error = await apiError(from: performer)

        #expect(error?.code == TamgaError.APIError.unknownCode)
        #expect(error?.detail == "something went wrong")
    }

    @Test("only the first error is taken")
    func onlyTheFirstErrorIsTaken() async {
        let performer = MockPerformer()
        await performer.enqueue(status: 409,
                                body: "{\"errors\":[{\"code\":\"FIRST\"},{\"code\":\"SECOND\"}]}")

        #expect(await apiError(from: performer)?.code == "FIRST")
    }

    @Test("every documented server code round-trips")
    func everyDocumentedServerCodeRoundTrips() async {
        let codes = ["NOT_FOUND", "UNAUTHORIZED", "FORBIDDEN", "INTERNAL_SERVER_ERROR",
                     "KEY_TAKEN", "FINGERPRINT_TAKEN", "PID_TAKEN", "CHECK_IN_NOT_REQUIRED",
                     "TTL_INVALID", "LICENSE_NOT_ENCRYPTED", "LICENSE_KEY_MISSING",
                     "SCHEME_NOT_SUPPORTED", "DATASET_INVALID",
                     "SIGNING_KEY_MISSING", "SECRET_KEY_MISSING"]

        for code in codes {
            let performer = MockPerformer()
            await performer.enqueue(status: 400, body: "{\"errors\":[{\"code\":\"\(code)\"}]}")
            #expect(await apiError(from: performer)?.code == code)
        }
    }

    @Test("rate limiting surfaces as an ordinary api error once retries run out")
    func rateLimitingSurfacesAsOrdinaryApiErrorOnceRetriesRunOut() async {
        let performer = MockPerformer()
        await performer.enqueue(status: 429, body: "{\"errors\":[{\"code\":\"TOO_MANY_REQUESTS\"}]}",
                                headers: ["Retry-After": "0"])
        let client = TamgaClient.mocked(performer, maxRetries: 1)

        do {
            _ = try await client.validateByKey("K")
            Issue.record("expected a rate-limit failure")
        } catch let error as TamgaError {
            #expect(error.httpStatus == 429)
            #expect(error.apiCode == "TOO_MANY_REQUESTS")
        } catch {
            Issue.record("expected a TamgaError, got \(error)")
        }
    }

    @Test("a malformed success body is reported as malformed, not as an api error")
    func malformedSuccessBodyIsReportedAsMalformed() async {
        let performer = MockPerformer()
        await performer.enqueue(status: 200, body: "not json at all")
        let client = TamgaClient.mocked(performer)

        do {
            _ = try await client.checkIn("lic-1")
            Issue.record("expected a decode failure")
        } catch let error as TamgaError {
            guard case .malformedResponse = error else {
                Issue.record("expected .malformedResponse, got \(error)")
                return
            }
        } catch {
            Issue.record("expected a TamgaError, got \(error)")
        }
    }

    @Test("error descriptions surface the code and detail")
    func errorDescriptionsSurfaceCodeAndDetail() {
        let metadata = ResponseMetadata(tamgaVersion: nil, tamgaEdition: nil,
                                        tamgaMode: nil, requestId: nil)
        let withDetail = TamgaError.api(TamgaError.APIError(
            code: "NOT_FOUND", httpStatus: 404, detail: "gone", title: nil, id: nil,
            pointer: nil, responseMetadata: metadata))
        let withoutDetail = TamgaError.api(TamgaError.APIError(
            code: "FORBIDDEN", httpStatus: 403, detail: nil, title: nil, id: nil,
            pointer: nil, responseMetadata: metadata))

        #expect(withDetail.errorDescription == "NOT_FOUND: gone")
        #expect(withoutDetail.errorDescription == "FORBIDDEN")
        #expect(TamgaError.transport(message: "boom", underlying: nil).errorDescription == "boom")
    }

    @Test("a 404 is recognized as not-found however its body decoded")
    func notFoundIsRecognizedHoweverItsBodyDecoded() {
        let metadata = ResponseMetadata(tamgaVersion: nil, tamgaEdition: nil,
                                        tamgaMode: nil, requestId: nil)
        func apiError(code: String, status: Int) -> TamgaError {
            .api(TamgaError.APIError(code: code, httpStatus: status, detail: nil, title: nil,
                                     id: nil, pointer: nil, responseMetadata: metadata))
        }

        // A ping's 404 is the only signal that a machine row is gone.
        // HeartbeatStatus.dead is not one: that machine still holds its seat.
        #expect(apiError(code: TamgaAPIErrorCode.notFound, status: 404).isNotFound)
        // A 404 whose body was missing or unreadable still counts.
        #expect(apiError(code: TamgaError.APIError.unknownCode, status: 404).isNotFound)
        #expect(!apiError(code: TamgaAPIErrorCode.forbidden, status: 403).isNotFound)
        #expect(!TamgaError.transport(message: "boom", underlying: nil).isNotFound)
    }

    @Test("missing response headers read as empty rather than failing")
    func missingResponseHeadersReadAsEmpty() {
        let metadata = ResponseMetadata(tamgaVersion: nil, tamgaEdition: nil,
                                        tamgaMode: nil, requestId: nil)

        #expect(metadata.requestId.isEmpty)
        #expect(metadata.tamgaEdition.isEmpty)
        #expect(metadata.tamgaMode.isEmpty)
        #expect(metadata.tamgaVersion.isEmpty)
    }

    @Test("a numeric status decodes the same as the string the server renders")
    func numericStatusDecodesLikeAString() async {
        // JSON:API renders status as "422"; the D18 fixture sends 422. Both
        // must keep the code -- a failed decode would hide it behind UNKNOWN.
        let bodies = [
            "{\"errors\":[{\"status\":\"422\",\"code\":\"SIGNING_KEY_MISSING\",\"detail\":\"no key\"}]}",
            "{\"errors\":[{\"status\":422,\"code\":\"SIGNING_KEY_MISSING\",\"detail\":\"no key\"}]}"
        ]
        for body in bodies {
            let performer = MockPerformer()
            await performer.enqueue(status: 422, body: body)
            let error = await apiError(from: performer)
            #expect(error?.code == TamgaAPIErrorCode.signingKeyMissing)
            #expect(error?.httpStatus == 422)
            #expect(error?.detail == "no key")
        }
    }

    @Test("scalar meta members are kept, nested ones dropped, absent meta is empty")
    func metaDecodesLeniently() async {
        // Exact wire shape from the API plan for a same-licence conflict,
        // padded with the member kinds a lenient reader has to survive.
        let performer = MockPerformer()
        await performer.enqueue(status: 409, body: """
        {"errors":[{"status":"409","code":"FINGERPRINT_TAKEN","detail":"taken",\
        "meta":{"machineId":"mach-7","count":2,"flag":true,"nested":{"x":1},"list":[1],"none":null}}]}
        """)
        let decoded = await apiError(from: performer)
        #expect(decoded?.meta == ["machineId": "mach-7", "count": "2", "flag": "true"])
        #expect(decoded?.code == TamgaAPIErrorCode.fingerprintTaken)

        // No meta at all: an empty dictionary, never nil, never a failure.
        let bare = MockPerformer()
        await bare.enqueue(status: 409, body: "{\"errors\":[{\"code\":\"FINGERPRINT_TAKEN\"}]}")
        #expect(await apiError(from: bare)?.meta == [:])

        // A malformed meta must not cost the code.
        let malformed = MockPerformer()
        await malformed.enqueue(status: 409,
                                body: "{\"errors\":[{\"code\":\"FINGERPRINT_TAKEN\",\"meta\":\"junk\"}]}")
        let survived = await apiError(from: malformed)
        #expect(survived?.code == TamgaAPIErrorCode.fingerprintTaken)
        #expect(survived?.meta == [:])
    }

    @Test("conflictingMachineId is set only for a FINGERPRINT_TAKEN that names one")
    func conflictingMachineIdIsNarrow() {
        let metadata = ResponseMetadata(tamgaVersion: nil, tamgaEdition: nil,
                                        tamgaMode: nil, requestId: nil)
        func apiError(code: String, meta: [String: String]) -> TamgaError {
            .api(TamgaError.APIError(code: code, httpStatus: 409, detail: nil, title: nil, id: nil,
                                     pointer: nil, responseMetadata: metadata, meta: meta))
        }
        let taken = TamgaAPIErrorCode.fingerprintTaken
        #expect(apiError(code: taken, meta: ["machineId": "mach-1"]).conflictingMachineId == "mach-1")
        #expect(apiError(code: taken, meta: [:]).conflictingMachineId == nil)
        #expect(apiError(code: taken, meta: ["machineId": ""]).conflictingMachineId == nil)
        #expect(apiError(code: "KEY_TAKEN", meta: ["machineId": "mach-1"]).conflictingMachineId == nil)
        #expect(TamgaError.transport(message: "boom", underlying: nil).conflictingMachineId == nil)
    }

    @Test("the key-material codes are recognized")
    func keyMaterialCodesAreRecognized() {
        let metadata = ResponseMetadata(tamgaVersion: nil, tamgaEdition: nil,
                                        tamgaMode: nil, requestId: nil)
        func apiError(code: String) -> TamgaError {
            .api(TamgaError.APIError(code: code, httpStatus: 422, detail: nil, title: nil, id: nil,
                                     pointer: nil, responseMetadata: metadata))
        }
        #expect(apiError(code: TamgaAPIErrorCode.signingKeyMissing).isSigningKeyMissing)
        #expect(!apiError(code: TamgaAPIErrorCode.secretKeyMissing).isSigningKeyMissing)
        #expect(apiError(code: TamgaAPIErrorCode.secretKeyMissing).apiCode == "SECRET_KEY_MISSING")
        #expect(!apiError(code: TamgaAPIErrorCode.forbidden).isSigningKeyMissing)
    }
}
