import Foundation

/// Entitlement endpoints and the lookup cache.
extension TamgaClient {
    // MARK: - Entitlements

    /// Lists a license's entitlements, capped at one page.
    ///
    /// **This route is not paginable, and `nextCursor` is always `nil`.** The
    /// listing is a union of directly attached and policy-inherited rows, so the
    /// server no longer applies a keyset predicate to it: `page[after]` is
    /// accepted for wire compatibility and then ignored, which makes a
    /// cursor loop refetch the same first page forever. `options.after` is kept
    /// on `ListOptions` for source compatibility but is **not sent** on this
    /// route.
    ///
    /// The consequence is a hard ceiling: `limit` is clamped server-side to 100,
    /// so a license with more than 100 effective entitlements cannot be
    /// enumerated in full through this endpoint at all. Treat a missing code as
    /// authoritative only below that ceiling.
    public func listEntitlements(
        licenseId: String,
        options: ListOptions = ListOptions()
    ) async throws -> Page<Entitlement> {
        let data = try await transport.getJSON(
            ["licenses", licenseId, "entitlements"],
            query: [URLQueryItem(name: "limit", value: String(Self.effectiveLimit(options)))])
        let envelope = try Self.decode(ListEnvelope<EntitlementAttributes>.self, from: data)
        return Page(nextCursor: nil, items: envelope.data.map(Entitlement.fromResource))
    }

    /// Fetches a single entitlement of a license by id.
    ///
    /// **Resolves direct attachments only.** The item route joins
    /// `license_entitlements` alone, so an entitlement that `listEntitlements`
    /// returned with `inherited == true` comes back as a `404` here.
    /// List-then-get-each is not a valid pattern against this resource.
    public func getEntitlement(licenseId: String, entitlementId: String) async throws
        -> Entitlement {
        let data = try await transport.getJSON(
            ["licenses", licenseId, "entitlements", entitlementId])
        return Entitlement.fromResource(
            try Self.decode(DataEnvelope<EntitlementAttributes>.self, from: data).data)
    }

    /// Whether a license carries an entitlement with the given code, caching
    /// the result for 60 seconds.
    ///
    /// Matching is on `code`, the stable developer-facing identifier. Never
    /// match on `name`, which is a display label that may collide or change.
    ///
    /// **Known limitation:** this fetches a single page of
    /// `entitlementLookupPageSize` entitlements, the server's maximum. A
    /// license carrying more is truncated here -- and cannot be enumerated in
    /// full by any other means either, because this route ignores `page[after]`
    /// (see `listEntitlements`). A `false` result is therefore authoritative
    /// only for a license holding at most `entitlementLookupPageSize` effective
    /// entitlements.
    public func hasEntitlement(licenseId: String, code: String) async throws -> Bool {
        if let cached = await entitlementCache.fresh(licenseId: licenseId) {
            return cached.contains(code)
        }
        let page = try await listEntitlements(
            licenseId: licenseId,
            options: ListOptions(limit: Self.entitlementLookupPageSize))
        let codes = Set(page.items.compactMap(\.code))
        await entitlementCache.store(codes, licenseId: licenseId)
        return codes.contains(code)
    }

    /// Drops the cached entitlement set for a license, forcing the next lookup
    /// to refetch.
    public func invalidateEntitlementCache(licenseId: String) async {
        await entitlementCache.invalidate(licenseId: licenseId)
    }
}
