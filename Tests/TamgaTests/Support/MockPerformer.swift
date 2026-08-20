import Foundation

@testable import Tamga

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A test double for `HTTPRequestPerforming`.
///
/// This is the seam the whole client suite runs through. It replaces
/// `URLSession` rather than stubbing it via `URLProtocol`, which is unreliable
/// on swift-corelibs-foundation and would make these tests Apple-only -- the
/// same reason the production seam is a protocol in the first place.
///
/// An `actor` because a `TamgaClient` is `Sendable` and its methods are called
/// from arbitrary tasks; recording requests through actor isolation keeps the
/// double race-free without any locking of its own.
actor MockPerformer: HTTPRequestPerforming {
    struct Stub {
        let status: Int
        let body: Data
        let headers: [String: String]

        init(status: Int = 200, body: String = "", headers: [String: String] = [:]) {
            self.status = status
            self.body = Data(body.utf8)
            self.headers = headers
        }
    }

    private var stubs: [Stub] = []
    private(set) var requests: [URLRequest] = []

    /// Queues a response. Requests consume stubs in order; once they run out,
    /// the last stub repeats so a test does not have to queue an exact count.
    func enqueue(_ stub: Stub) {
        stubs.append(stub)
    }

    func enqueue(status: Int = 200, body: String = "", headers: [String: String] = [:]) {
        enqueue(Stub(status: status, body: body, headers: headers))
    }

    var requestCount: Int { requests.count }

    func request(at index: Int) -> URLRequest? {
        index < requests.count ? requests[index] : nil
    }

    /// The body of a recorded request, as text.
    func requestBody(at index: Int) -> String {
        guard let data = request(at: index)?.httpBody else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }

    nonisolated func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await record(request)
    }

    private func record(_ request: URLRequest) throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        let stub: Stub
        if stubs.count > 1 {
            stub = stubs.removeFirst()
        } else if let only = stubs.first {
            stub = only
        } else {
            stub = Stub(status: 200, body: "{}")
        }
        guard let url = request.url,
              let response = HTTPURLResponse(url: url, statusCode: stub.status,
                                             httpVersion: "HTTP/1.1",
                                             headerFields: stub.headers)
        else {
            throw TamgaError.transport(message: "Could not build a stub response.",
                                       underlying: nil)
        }
        return (stub.body, response)
    }
}

extension TamgaClient {
    /// Builds a client wired to a mock performer, with deterministic backoff.
    static func mocked(
        _ performer: MockPerformer,
        auth: AuthTransport = .licenseKey("lic-abc"),
        accountId: String = "acct-123",
        host: String = "https://api.example.test",
        otp: String? = nil,
        maxRetries: Int = Transport.defaultMaxRetries,
        maxResponseBytes: Int = Transport.maxResponseBytes,
        now: @escaping @Sendable () -> Date = { Date() }
    ) -> TamgaClient {
        TamgaClient(
            accountId: accountId,
            auth: auth,
            host: host,
            otp: otp,
            maxRetries: maxRetries,
            performer: performer,
            maxResponseBytes: maxResponseBytes,
            jitterMilliseconds: { 0 },
            now: now
        )
    }
}

enum Fixtures {
    static func licenseWithMeta(code: String = "VALID", valid: Bool = true) -> String {
        """
        {"data":{"id":"lic-1","type":"licenses","attributes":{"key":"K","status":"ACTIVE",\
        "machines_count":2,"suspended":false,"uses":3}},\
        "meta":{"ts":"2026-08-20T10:00:00Z","valid":\(valid),"detail":"d","code":"\(code)"}}
        """
    }

    static let machine = """
    {"data":{"id":"mach-1","type":"machines","attributes":{"fingerprint":"fp-1",\
    "heartbeat_status":"ALIVE","cores":4,"memory":8589934592,"hostname":"box"}}}
    """

    static let license = """
    {"data":{"id":"lic-1","type":"licenses","attributes":{"key":"K"}}}
    """
}
