import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// `{"data": <resource>}`.
struct DataEnvelope<Attributes: Decodable>: Decodable {
    let data: JSONAPIResource<Attributes>
}

/// `{"data": <resource>, "meta": <meta>}`.
struct DataMetaEnvelope<Attributes: Decodable, Meta: Decodable>: Decodable {
    let data: JSONAPIResource<Attributes>
    let meta: Meta?
}

/// `{"data": [<resource>, ...]}`.
struct ListEnvelope<Attributes: Decodable>: Decodable {
    let data: [JSONAPIResource<Attributes>]
}

/// The `meta` block of a generate-offline-proof response.
struct ProofMeta: Decodable {
    let proof: String?
}

/// The attribute bag of a `license-files`/`machine-files` checkout resource.
///
/// `includes` is always `[]` server-side -- there is no working `include[]`
/// parameter despite the field existing. Do not build an
/// embedded-relationships feature on it.
struct CheckoutFileAttributes: Decodable {
    let certificate: String?
    let algorithm: String?
    let ttl: Int64?
    let expiry: String?
    let issued: String?
}

/// Session policy for the client this SDK builds: refuse redirects, and refuse
/// a response that announces more data than the client is willing to hold.
final class SessionPolicyDelegate: NSObject, URLSessionTaskDelegate, URLSessionDataDelegate,
    Sendable {
    private let maxResponseBytes: Int

    init(maxResponseBytes: Int) {
        self.maxResponseBytes = maxResponseBytes
        super.init()
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

    /// Cancels a response whose declared length is over the cap, before the body
    /// is transferred.
    ///
    /// `Transport` also checks the delivered size, but that check happens after
    /// `URLSession` has already buffered the whole body in memory -- which is
    /// exactly the allocation the cap exists to prevent. Cancelling here is what
    /// makes the limit bite.
    ///
    /// A body with no declared length still gets buffered before `Transport`
    /// sees it. Closing that fully would mean streaming the response rather than
    /// using the completion-handler API, which is a larger change than it
    /// sounds on Linux; the post-hoc check remains the backstop for it.
    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        if response.expectedContentLength > Int64(maxResponseBytes) {
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }
}
