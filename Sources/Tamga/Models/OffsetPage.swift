import Foundation

/// The `meta.page` block an offset-paginated collection carries.
///
/// **Only the machine collection sends this.** Everything else this SDK lists
/// -- entitlements, a machine's components, a machine's processes -- returns a
/// bare `data` array with no `meta` and no `links`, which is why `Page` has to
/// synthesize its cursor. Do not generalize either shape to the other: the SDK
/// once assumed keyset everywhere and paged an entitlement list forever, and
/// assuming offset everywhere would read a `nil` meta as "one page of zero".
public struct PageInfo: Equatable, Sendable {
    /// The 1-based page number this response is. Wire name `number`.
    public let number: Int
    /// How many items a full page holds. Wire name `size`.
    public let size: Int
    /// How many items match the filters in total. Wire name `total`.
    public let total: Int
    /// How many pages that total spans. Wire name `totalPages` -- the one
    /// camelCase key in this block, the other three being single words.
    public let totalPages: Int

    /// Whether a further page exists.
    public var hasNextPage: Bool { number < totalPages }

    /// The page number to request next, or `nil` on the last page.
    public var nextPageNumber: Int? { hasNextPage ? number + 1 : nil }
}

/// A single page of an offset-paginated list, plus the server's own count of
/// what it is a page of.
///
/// Distinct from `Page`, which is keyset and synthesizes its cursor because the
/// routes it serves report no pagination metadata at all. Advance this one by
/// asking for `pageInfo.nextPageNumber`.
public struct OffsetPage<Item: Sendable>: Sendable {
    /// The server's pagination metadata, or `nil` if the response carried no
    /// `meta.page` block.
    ///
    /// Optional rather than defaulted, so a route that stops sending the block
    /// reads as "unknown" instead of silently reporting a single empty page.
    public let pageInfo: PageInfo?
    /// This page's items.
    public let items: [Item]
}

extension OffsetPage: Equatable where Item: Equatable {}

/// The `meta` block of an offset-paginated list response.
struct PageMetaBlock: Decodable {
    struct PageBlock: Decodable {
        let number: Int?
        let size: Int?
        let total: Int?
        let totalPages: Int?
    }

    let page: PageBlock?

    var pageInfo: PageInfo? {
        guard let page else { return nil }
        return PageInfo(number: page.number ?? 1, size: page.size ?? 0,
                        total: page.total ?? 0, totalPages: page.totalPages ?? 0)
    }
}
