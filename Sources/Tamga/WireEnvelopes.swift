import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// `{"data": <resource>}`.
struct DataEnvelope<Attributes: Decodable>: Decodable {
    let data: JSONAPIResource<Attributes>
}

/// `{"data": <resource>, "meta": <meta>}`.
struct DataMetaEnvelope<Attributes: Decodable, Meta: Decodable>: Decodable {
    let data: JSONAPIResource<Attributes>
    let meta: Meta?
}

/// `{"data": [<resource>, ...]}`.
struct ListEnvelope<Attributes: Decodable>: Decodable {
    let data: [JSONAPIResource<Attributes>]
}

/// The `meta` block of a generate-offline-proof response.
struct ProofMeta: Decodable {
    let proof: String?
}

/// The attribute bag of a `license-files`/`machine-files` checkout resource.
///
/// `includes` is always `[]` server-side -- there is no working `include[]`
/// parameter despite the field existing. Do not build an
/// embedded-relationships feature on it.
struct CheckoutFileAttributes: Decodable {
    let certificate: String?
    let algorithm: String?
    let ttl: Int64?
    let expiry: String?
    let issued: String?
}

/// `{"data": [<resource>, ...], "meta": {"page": {...}}}` -- the offset-paginated
/// list shape, which only the machine collection uses.
struct ListPageEnvelope<Attributes: Decodable>: Decodable {
    let data: [JSONAPIResource<Attributes>]
    let meta: PageMetaBlock?
}
