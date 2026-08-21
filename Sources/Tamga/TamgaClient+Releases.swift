import Foundation

/// The outcome of an auto-update check.
///
/// A two-case enum rather than an optional `Release`, because the "nothing"
/// case is the one that gets misread. `nil` invites *"you are up to date"*,
/// and that is precisely what this answer does **not** mean -- see
/// `noneAvailable`.
public enum UpgradeCheckResult: Equatable, Sendable {
    /// A release this caller should upgrade to.
    case upgrade(Release)

    /// No upgrade is available **to you**. Read that literally.
    ///
    /// The server answers `204 No Content` in two different situations and
    /// refuses, by design, to distinguish them:
    ///
    /// 1. There is no newer release matching the query.
    /// 2. There **is** a newer release, but this licence is not entitled to it
    ///    -- an expired licence under a policy whose `expirationStrategy` stops
    ///    it receiving builds published after its expiry.
    ///
    /// The second case answers `204` rather than a rejection precisely so a
    /// denial cannot leak *"a newer version exists but you cannot have it"*.
    /// There is no client-side way to tell the two apart, and there should not
    /// be.
    ///
    /// So do not render this as "You're on the latest version". Render it as
    /// "No update is available", and hang a renewal prompt off the licence's
    /// own `expiry` or validation verdict instead.
    case noneAvailable

    /// The release when there is one, `nil` otherwise.
    ///
    /// A convenience for call sites that only want the happy path. Do not use
    /// it to reconstruct a boolean "up to date" -- see `noneAvailable`.
    public var release: Release? {
        if case .upgrade(let release) = self { return release }
        return nil
    }
}

/// The auto-update check.
extension TamgaClient {
    /// Asks whether there is a release this caller should upgrade to.
    ///
    /// - Returns: `.upgrade(release)`, or `.noneAvailable` -- whose meaning is
    ///   narrower than it looks. Read `UpgradeCheckResult.noneAvailable` before
    ///   branching on it.
    ///
    /// ## Not every "no" arrives as `.noneAvailable`
    ///
    /// - `403 FORBIDDEN` -- the licence is **suspended**. A third outcome, not
    ///   folded into the `204`: a suspended licence is told, an expired one is
    ///   not.
    /// - `404 NOT_FOUND` -- no such product in this account. Usually
    ///   `options.productId` was given a product *code* instead of its UUID.
    /// - `422 INVALID_VERSION` / `INVALID_CONSTRAINT` -- `version` or
    ///   `constraint` did not parse as semver.
    /// - `400` with `code == TamgaError.APIError.unknownCode` -- a required
    ///   query parameter was missing or unparseable. This route rejects before
    ///   the JSON:API error layer runs, so the body is plain text and the code
    ///   degrades to the synthetic `UNKNOWN` rather than naming the field.
    /// - `401` / `403` from the product's distribution strategy -- an `Open`
    ///   product needs no credential, a `Licensed` one needs a credential
    ///   holding `release.read`, and a `Closed` one admits only admin,
    ///   developer and product tokens.
    ///
    /// ## Authentication
    ///
    /// The route takes **optional** auth, so an `Open` product's updates stay
    /// reachable with no credential at all -- otherwise every auto-updater in
    /// the field would break the moment a key expired. This SDK still sends
    /// whatever credential it was configured with, which is what makes the
    /// entitlement check behind `.noneAvailable` apply at all.
    public func checkForUpgrade(
        _ options: UpgradeCheckOptions
    ) async throws -> UpgradeCheckResult {
        let data = try await transport.getJSONOrNoContent(
            ["releases", "actions", "upgrade"], query: options.queryItems)
        guard let data else { return .noneAvailable }
        return .upgrade(Release.fromResource(
            try Self.decode(DataEnvelope<ReleaseAttributes>.self, from: data).data))
    }
}
