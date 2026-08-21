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
    /// identical.** The server exempts `/v1/health` from both the credential
    /// check and the `Host`-header check. So if every other call is failing
    /// with `403` and *"The Host header does not match any configured host"*
    /// while this call succeeds, the fault is the server's `TAMGA_ALLOWED_HOSTS`
    /// configuration -- not the caller's credential, not the account id, and
    /// not the network. If this call fails too, the problem is further out:
    /// DNS, TLS, a proxy, or the server being down.
    ///
    /// The configured credential is still sent, the same as on every other
    /// route, because this SDK sends what it was configured with rather than
    /// deciding per route which calls deserve a credential. The route being
    /// public means the call succeeds whether or not that credential is any
    /// good -- which is exactly what makes the diagnostic above work.
    public func health() async throws -> HealthStatus {
        let data = try await transport.getRootJSON(["v1", "health"])
        return try Self.decode(HealthStatusWire.self, from: data).flattened
    }
}
