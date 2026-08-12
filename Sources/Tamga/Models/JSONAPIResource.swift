import Foundation

/// The generic JSON:API resource envelope shape (`{ id, type, attributes }`)
/// this SDK's endpoints and offline checkout files both wrap real resources
/// in. Relationships are intentionally not modeled here -- nothing in this
/// SDK's current scope (offline checkout decode) reads them; add a
/// `relationships` field here if/when a caller needs relationship IDs
/// (e.g. `license.policy`), following this same generic-over-`Attributes`
/// shape.
struct JSONAPIResource<Attributes: Decodable>: Decodable {
    let id: String
    let attributes: Attributes?
}

/// The `{"data": <resource>}` payload embedded in a plain (unencrypted)
/// offline checkout file, generic over the wrapped resource's attribute type.
struct JSONAPIPayload<Attributes: Decodable>: Decodable {
    let data: JSONAPIResource<Attributes>
}
