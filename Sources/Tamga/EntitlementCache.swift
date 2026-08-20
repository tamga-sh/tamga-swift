import Foundation

/// A short-lived, per-license cache of entitlement codes backing
/// `TamgaClient.hasEntitlement`.
///
/// Entries live for `ttl`. Eviction happens on read plus explicit
/// invalidation; there is no background sweep, no size bound, and no eviction
/// policy. That is deliberate -- entries are keyed by license id, and an
/// embedded SDK sees a small, usually singleton set.
///
/// An `actor` rather than a lock: the cache is read from async endpoint methods
/// on arbitrary tasks, and actor isolation gives that safety without any
/// possibility of holding a lock across the network call that populates it.
/// Two concurrent misses for the same license will therefore both fetch, and
/// the last writer wins. That is accepted rather than deduplicated.
actor EntitlementCache {
    /// How long a fetched entitlement set stays fresh.
    static let ttl: TimeInterval = 60

    private struct Entry {
        let codes: Set<String>
        let fetchedAt: Date
    }

    private var entries: [String: Entry] = [:]
    private let now: @Sendable () -> Date

    init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    /// The cached codes for a license, or `nil` when absent or stale.
    func fresh(licenseId: String) -> Set<String>? {
        guard let entry = entries[licenseId] else { return nil }
        guard now().timeIntervalSince(entry.fetchedAt) < Self.ttl else { return nil }
        return entry.codes
    }

    /// Stores a freshly fetched code set for a license.
    func store(_ codes: Set<String>, licenseId: String) {
        entries[licenseId] = Entry(codes: codes, fetchedAt: now())
    }

    /// Drops the cached entry for a license, forcing the next lookup to
    /// refetch.
    func invalidate(licenseId: String) {
        entries.removeValue(forKey: licenseId)
    }
}
