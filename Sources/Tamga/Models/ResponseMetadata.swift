import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Diagnostic response headers carried alongside every API error.
///
/// A missing header is the empty string rather than an error -- this is
/// support and debugging metadata, not something correctness depends on.
///
/// Deliberately not modeled: `Tamga-Environment`, a planned feature no server
/// code path reads yet.
///
/// `X-RateLimit-*` is not modeled either, but **not** for the reason this
/// comment used to give. It said those headers were "present in the server's
/// CORS allowlist only, never set by a handler". That was true once and is not
/// now: `x-ratelimit-limit`, `-remaining`, `-reset` and `-window` are set by
/// the rate-limit middleware on every response it sees. They are still absent
/// when no limiter is configured -- the middleware returns early in that case --
/// so anything reading them has to treat them as optional. Not modeling them is
/// a scope decision; `Transport` already handles `429` and `Retry-After`
/// without them.
public struct ResponseMetadata: Equatable, Sendable {
    /// The `Tamga-Version` the server echoed back.
    public let tamgaVersion: String
    /// `Tamga-Edition` -- `"EE"` or `"CE"`.
    public let tamgaEdition: String
    /// `Tamga-Mode` -- `"singleplayer"` or `"multiplayer"`.
    public let tamgaMode: String
    /// `X-Request-Id`. Log this: it correlates a client-side error with
    /// server-side logs.
    public let requestId: String

    init(tamgaVersion: String?, tamgaEdition: String?, tamgaMode: String?, requestId: String?) {
        self.tamgaVersion = tamgaVersion ?? ""
        self.tamgaEdition = tamgaEdition ?? ""
        self.tamgaMode = tamgaMode ?? ""
        self.requestId = requestId ?? ""
    }

    init(response: HTTPURLResponse) {
        self.init(
            tamgaVersion: response.value(forHTTPHeaderField: "Tamga-Version"),
            tamgaEdition: response.value(forHTTPHeaderField: "Tamga-Edition"),
            tamgaMode: response.value(forHTTPHeaderField: "Tamga-Mode"),
            requestId: response.value(forHTTPHeaderField: "X-Request-Id")
        )
    }
}
