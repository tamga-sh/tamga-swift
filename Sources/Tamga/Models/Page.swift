import Foundation

/// Keyset-pagination request options shared by `listComponents` and
/// `listEntitlements`. The server caps `limit` at 100.
public struct ListOptions: Equatable, Sendable {
    /// An opaque cursor from a previous page's `nextCursor`.
    public var after: String?
    /// Requested page size. Zero accepts the server default.
    public var limit: Int

    /// Creates list options.
    public init(after: String? = nil, limit: Int = 0) {
        self.after = after
        self.limit = limit
    }
}

/// A single page of a keyset-paginated list.
///
/// **Pagination is synthetic.** These endpoints carry no cursor metadata or
/// links of their own, so `nextCursor` is set to the last item's id if and only
/// if a full page was returned. It is `nil` on a short or empty page, which is
/// the signal that there is nothing further to fetch.
public struct Page<Item: Sendable>: Sendable {
    /// The cursor to pass as the next request's `after`, or `nil` if done.
    public let nextCursor: String?
    /// This page's items.
    public let items: [Item]

    init(nextCursor: String?, items: [Item]) {
        self.nextCursor = nextCursor
        self.items = items
    }
}

extension Page: Equatable where Item: Equatable {}
