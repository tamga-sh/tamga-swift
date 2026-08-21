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

/// The `{"data": <resource>, "meta": <claims>}` payload embedded in an offline
/// checkout file, generic over the wrapped resource's attribute type.
struct JSONAPIPayload<Attributes: Decodable>: Decodable {
    let data: JSONAPIResource<Attributes>
    /// Present on format-v2 license files AND on format-v2 machine files --
    /// `check_out_machine.rs` signs the same `LicenseFileClaims` shape into
    /// the machine payload. Absent on a pre-v2 file of either kind, which is
    /// rejected. Optional here only so that rejection can be a clear
    /// `offlineFileFormat` error rather than a decode failure.
    let meta: LicenseFileClaims?
}

/// The claims carried *inside* the signed bytes of a `.lic` or `.machine`
/// file. Named for the license file because that is where the server's type is
/// defined (`license_file.rs`'s `LicenseFileClaims`); machine checkout signs
/// the identical struct.
///
/// These are the point of format v2. In v1 the `ttl`/`expiry` a caller asked
/// for lived only in the JSON:API envelope around the certificate, never inside
/// the signed bytes -- so a 24-hour trial file was cryptographically valid
/// forever, because the client is the attacker and any check built on the
/// envelope is bypassed by keeping (or redistributing) the raw certificate
/// string. Unlike the envelope, these cannot be edited by whoever holds the
/// file.
public struct LicenseFileClaims: Decodable, Equatable, Sendable {
    /// Issued-at, seconds since the Unix epoch.
    public let iat: Int64
    /// Expiry, seconds since the Unix epoch. `nil` means the file never
    /// expires -- checkout was made without a `ttl`. Legitimate, not an error:
    /// both `check_out_license` and `check_out_machine` set this from an
    /// `Option<ttl>`.
    public let exp: Int64?
    /// Unique per checkout -- usable for replay detection.
    public let jti: String
    /// Identifies the signing key, so a file survives a key rotation.
    public let kid: String
}
