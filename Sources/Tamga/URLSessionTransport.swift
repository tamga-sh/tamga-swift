import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Performs one HTTP request.
///
/// This is the seam every test double replaces. It is a protocol rather than a
/// concrete `URLSession` because `URLProtocol`-based stubbing is unreliable on
/// swift-corelibs-foundation, so a Linux-supporting package cannot depend on
/// it -- and a protocol seam is clearer anyway.
public protocol HTTPRequestPerforming: Sendable {
    /// Sends `request` and returns its body and response.
    func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// The default `HTTPRequestPerforming`, backed by `URLSession`.
///
/// Owns its session so the policy delegate below is guaranteed to be wired in.
/// A session built elsewhere and handed over could silently lack it.
public struct URLSessionTransport: HTTPRequestPerforming {
    private let session: URLSession
    private let policy: SessionPolicyDelegate

    /// Builds a session enforcing this SDK's transport policy: no redirects,
    /// and a hard ceiling on response size.
    public init(configuration: URLSessionConfiguration, maxResponseBytes: Int) {
        let policy = SessionPolicyDelegate(maxResponseBytes: maxResponseBytes)
        self.policy = policy
        self.session = URLSession(configuration: configuration, delegate: policy,
                                  delegateQueue: nil)
    }

    public func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        // Deliberately the delegate-driven task, NOT
        // `dataTask(with:completionHandler:)` and NOT `URLSession.data(for:)`.
        //
        // The completion-handler form buffers the whole body before handing it
        // over, and -- confirmed empirically, not assumed -- suppresses the
        // data-level delegate callbacks entirely, so a size check has nothing
        // to hook into and can only run once the memory is already spent. The
        // async form has had availability gaps on swift-corelibs-foundation.
        // Driving the task through the delegate is what makes the cap real and
        // keeps one code path on every platform.
        let task = session.dataTask(with: request)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                policy.register(task: task, continuation: continuation)
                task.resume()
            }
        } onCancel: {
            // Without this, cancelling the calling Task abandons the await but
            // leaves the request running.
            task.cancel()
        }
    }
}

/// Session policy for the client this SDK builds: refuse redirects, and refuse
/// a response body larger than the client is willing to hold.
///
/// Also the transport's data pump. Because the task is delegate-driven rather
/// than completion-handler-driven, this type accumulates the body itself, which
/// is precisely what lets it stop mid-transfer.
final class SessionPolicyDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private struct State {
        var data = Data()
        var response: HTTPURLResponse?
        var overflowed = false
        let continuation: CheckedContinuation<(Data, HTTPURLResponse), any Error>
    }

    private let maxResponseBytes: Int
    private let lock = NSLock()
    private var states: [Int: State] = [:]

    init(maxResponseBytes: Int) {
        self.maxResponseBytes = maxResponseBytes
        super.init()
    }

    func register(task: URLSessionTask,
                  continuation: CheckedContinuation<(Data, HTTPURLResponse), any Error>) {
        lock.lock()
        defer { lock.unlock() }
        states[task.taskIdentifier] = State(continuation: continuation)
    }

    /// Resumes a task's continuation exactly once and forgets its state.
    private func finish(_ taskIdentifier: Int,
                        _ result: Result<(Data, HTTPURLResponse), any Error>) {
        lock.lock()
        let state = states.removeValue(forKey: taskIdentifier)
        lock.unlock()
        guard let state else { return }
        state.continuation.resume(with: result)
    }

    /// Refuses every redirect, so a `3xx` cannot carry credentials to a host the
    /// caller never configured.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    /// Rejects a response that announces more data than the cap allows, before
    /// any of the body transfers.
    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        lock.lock()
        if var state = states[dataTask.taskIdentifier] {
            state.response = response as? HTTPURLResponse
            if response.expectedContentLength > Int64(maxResponseBytes) {
                state.overflowed = true
            }
            states[dataTask.taskIdentifier] = state
        }
        let overflowed = states[dataTask.taskIdentifier]?.overflowed ?? false
        lock.unlock()

        completionHandler(overflowed ? .cancel : .allow)
    }

    /// Accumulates the body, stopping the transfer the moment it crosses the
    /// cap. A body that declares no length is bounded here rather than after
    /// the fact.
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        var shouldCancel = false
        if var state = states[dataTask.taskIdentifier] {
            state.data.append(data)
            if state.data.count > maxResponseBytes {
                state.overflowed = true
                state.data = Data()
                shouldCancel = true
            }
            states[dataTask.taskIdentifier] = state
        }
        lock.unlock()

        if shouldCancel {
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        lock.lock()
        let state = states[task.taskIdentifier]
        lock.unlock()
        guard let state else { return }

        if state.overflowed {
            finish(task.taskIdentifier, .failure(TamgaError.transport(
                message: "Server response body exceeded this client's \(maxResponseBytes) byte "
                    + "limit; the transfer was cancelled.", underlying: nil)))
            return
        }
        if let error {
            finish(task.taskIdentifier, .failure(error))
            return
        }
        guard let response = state.response ?? task.response as? HTTPURLResponse else {
            finish(task.taskIdentifier, .failure(TamgaError.transport(
                message: "Response was not an HTTP response.", underlying: nil)))
            return
        }
        finish(task.taskIdentifier, .success((state.data, response)))
    }
}
