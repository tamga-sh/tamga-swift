import Foundation

/// Entitlement endpoints and the lookup cache.
extension TamgaClient {
    // MARK: - Entitlements

    /// Lists a license's entitlements, one keyset-paginated page at a time.
    public func listEntitlements(
        licenseId: String,
        options: ListOptions = ListOptions()
    ) async throws -> Page<Entitlement> {
        let data = try await transport.getJSON(["licenses", licenseId, "entitlements"],
                                               query: Self.pageQuery(options))
        let envelope = try Self.decode(ListEnvelope<EntitlementAttributes>.self, from: data)
        return Page(nextCursor: Self.synthesizeCursor(envelope.data, options: options),
                    items: envelope.data.map(Entitlement.fromResource))
    }

    /// Fetches a single entitlement of a license by id.
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
    /// license carrying more is silently truncated here; paginate
    /// `listEntitlements` directly if that is a possibility.
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
