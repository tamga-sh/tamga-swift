import Foundation

/// The server's liveness probe.
extension TamgaClient {
    /// Reads `GET /v1/health`.
    ///
    /// This is the one route this SDK calls that is **not** under
    /// `/v1/accounts/{accountId}`, and the one whose body is not JSON:API. The
    /// account id configured on the client is unused here.
    ///
    /// **Why it is worth having: it separates two failures that otherwise look
    /// identical.** `/v1/health` is on the server's public-route list and is one
    /// of only two paths that bypass the `Host`-header check. So if every other
    /// call is failing with `403` and *"The Host header does not match any
    /// configured host"* while this call succeeds, the fault is the server's
    /// `TAMGA_ALLOWED_HOSTS` configuration -- not the caller's credential, not
    /// the account id, and not the network. If this call fails too, the problem
    /// is further out: DNS, TLS, a proxy, or the server being down.
    ///
    /// Note "on the public-route list", not "exempt from the credential check".
    /// Those are not the same thing, and the difference is the whole reason for
    /// the paragraph below.
    ///
    /// **No credential is sent, and that is what makes the diagnostic work.**
    /// This is the one route in this SDK that goes out anonymously.
    ///
    /// Sending one would defeat the purpose. The server resolves a request's
    /// credential *before* it checks whether the route is public, and
    /// propagates a resolution failure straight out
    /// (`require_auth.rs:120-127`), so an unusable credential rejects a public
    /// route just as hard as a private one. Worse, whether that resolution
    /// happens at all on a path with no `{account_id}` segment depends on the
    /// server's mode, and the exposed one is the default: in **singleplayer**
    /// -- the server's `#[default]` -- the account id comes from configuration
    /// rather than the path, so it is present for every path including this
    /// one, and a licence key under a default policy is refused with
    /// `401 LICENSE_NOT_ALLOWED` before the public-route check is ever
    /// consulted.
    ///
    /// A probe that fails whenever the caller's credential is the thing under
    /// suspicion tells you nothing you did not already know. Anonymous, it
    /// answers whenever the server and the host configuration are sound, which
    /// is the question being asked. Nothing is given up: the route is public,
    /// returns no account data, and is exempt from the host check.
    public func health() async throws -> HealthStatus {
        let data = try await transport.getRootJSON(["v1", "health"])
        return try Self.decode(HealthStatusWire.self, from: data).flattened
    }
}
