/// `Machine.swift`
///
/// STUB -- scaffolding only. No implementation yet.
///
/// Intended contents once implemented:
///
/// - `Machine`: full JSON:API resource attributes (fingerprint, name, ip,
///   hostname, platform, cores, memory, disk, metadata, heartbeat_status,
///   etc. -- see docs/sdk.md §5).
/// - `HeartbeatStatus` enum: `NOT_STARTED` (never pinged) -> `ALIVE` (pinged
///   within window) -> `DEAD` (window elapsed) -> `RESURRECTED` (a new ping
///   arrived after a death event was already recorded).
///
/// The heartbeat window is a hardcoded 600s (10 min) server-side, NOT driven
/// by `policy.heartbeat_duration` (see docs/sdk.md's "Known Server-Side Gaps"
/// item 8) -- a heartbeat scheduler helper (see `HeartbeatScheduler.swift`)
/// should ping at roughly 1/3 of that interval, not the full window.
///
/// Treat `DEAD` as "machine likely deleted server-side -- re-activate rather
/// than retry ping," since `HeartbeatCullStrategy.DEACTIVATE_DEAD` (see
/// `Policy.swift`) may have already removed the row.
public enum Machine {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Section H.
}
