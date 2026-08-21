import Foundation

/// The body of `GET /v1/health`.
///
/// **This response is not JSON:API.** The handler returns a flat
/// `{"status": ..., "version": ..., "uptime_secs": ...}` object -- no `data`
/// envelope, no `type`, no `attributes` -- so it does not go through the
/// envelope decoder every other endpoint uses. `quickValidate` is the only
/// other flat body in this SDK.
public struct HealthStatus: Equatable, Sendable {
    /// `"ok"` on the current server.
    ///
    /// A `String` rather than a closed enum on purpose: the handler hardcodes
    /// one value today, and a probe whose entire job is answering while things
    /// are going wrong must not fail to decode the day it starts answering
    /// something else.
    public let status: String

    /// The server's own build version, e.g. `"1.8.3"`.
    ///
    /// **Not the `Tamga-Version` API version this SDK sends.** The two are
    /// unrelated strings and neither can be derived from the other.
    public let version: String?

    /// Seconds since the server process started.
    ///
    /// Resets on every deploy or restart, so a small value here explains an
    /// otherwise mysterious burst of cold-cache latency or a dropped in-flight
    /// request.
    public let uptimeSeconds: Int64?
}

/// The wire shape of the health body. The shared decoder's
/// `.convertFromSnakeCase` maps `uptime_secs` onto `uptimeSecs`.
struct HealthStatusWire: Decodable {
    let status: String?
    let version: String?
    let uptimeSecs: Int64?

    var flattened: HealthStatus {
        HealthStatus(status: status ?? "", version: version, uptimeSeconds: uptimeSecs)
    }
}
