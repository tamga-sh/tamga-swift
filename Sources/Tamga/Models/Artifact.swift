import Foundation

/// An uploaded release payload -- the actual bytes an updater downloads.
///
/// ## Wire naming, which is a trap here specifically
///
/// The server declares `#[serde(rename_all = "camelCase")]` on this attribute
/// bag **and then overrides two fields explicitly**
/// (`artifacts/serializer.rs:20,34-37`), so the wire is neither uniformly
/// camelCase nor uniformly snake_case:
///
/// | Swift            | Wire          |
/// |------------------|---------------|
/// | `redirectURL`    | `redirectUrl` |
/// | `created`        | `created`     |
/// | `updated`        | `updated`     |
///
/// `created`/`updated` are **not** `createdAt`/`updatedAt`, despite the Rust
/// fields being `created_at`/`updated_at` -- the explicit `#[serde(rename)]`
/// wins over `rename_all`. `Release` has the same two names for the same
/// reason; `Machine` uses them too.
///
/// This SDK's shared decoder applies `.convertFromSnakeCase`, which leaves a
/// key containing no underscore exactly as it found it, so every wire name
/// above reaches `ArtifactAttributes` unchanged and that type declares **no
/// CodingKeys at all**. Adding them would break it rather than help: the
/// strategy rewrites the wire key *first* and lookup then compares the result
/// against the CodingKey's `stringValue`, so a CodingKey spelled
/// `redirect_url` would match nothing and decode `nil` -- the exact bug
/// `MachineAttributes` carries a comment about having had.
///
/// One consequence, measured rather than assumed: leaving the CodingKeys off
/// makes the decode *lenient across both spellings*. `redirect_url` is
/// rewritten to `redirectUrl` and lands on the same property, so this client
/// survives a server-side rename in either direction. The "defensive"
/// CodingKeys would have thrown that away as well as breaking the current
/// name.
///
/// `redirectURL` is renamed on this public type only, where nothing decodes it,
/// so the Swift-facing name can follow the API design guidelines' `URL`
/// capitalisation without touching the decode path.
public struct Artifact: Equatable, Sendable {
    /// The artifact's unique id.
    public let id: String
    /// The file's name, e.g. `"Acme-2.0.0.dmg"`.
    public let filename: String?
    /// The file's type, e.g. `"dmg"`. Matches `UpgradeCheckOptions.filetype`.
    public let filetype: String?
    /// Size in bytes.
    ///
    /// `Int64` rather than `Int`: the column is `BIGINT` and a 32-bit `Int`
    /// platform would overflow on a 3 GiB installer.
    public let filesize: Int64?
    /// The publisher's checksum. **This SDK does not verify it** -- it never
    /// holds the bytes. Whatever downloads the artifact should.
    public let checksum: String?
    /// Target platform, e.g. `"darwin"`. Matches `UpgradeCheckOptions.platform`.
    public let platform: String?
    /// Target architecture, e.g. `"arm64"`.
    public let arch: String?
    /// The publisher's detached signature over the bytes, when they set one.
    ///
    /// Opaque here. It is not one of the four signing schemes
    /// `Sources/Tamga/Checkout/` verifies and nothing in this SDK checks it.
    public let signature: String?
    /// Upload/publication status.
    public let status: String?
    /// Arbitrary publisher-set metadata.
    public let metadata: [String: JSONValue]?
    /// The presigned storage URL, when this artifact came back from a download
    /// action.
    ///
    /// **Absent on list and show** -- the server skips the key entirely there
    /// (`skip_serializing_if = "Option::is_none"`). Use
    /// `TamgaClient.downloadArtifact(_:ttl:)`, which returns it parsed and
    /// non-optional.
    ///
    /// **Fetch it with no credentials.** It carries its own signature in the
    /// query string and points at object storage, not at the API host.
    ///
    /// **This raw string is NOT scheme-validated.** It is whatever the response
    /// carried. `ArtifactDownload.url` is the checked form; prefer it, and
    /// validate the scheme yourself if you use this instead.
    public let redirectURL: String?
    /// When the artifact was created. Wire name `created`.
    public let created: Date?
    /// When the artifact was last updated. Wire name `updated`.
    public let updated: Date?

    static func fromResource(_ resource: JSONAPIResource<ArtifactAttributes>) -> Artifact {
        let attrs = resource.attributes
        return Artifact(
            id: resource.id,
            filename: attrs?.filename,
            filetype: attrs?.filetype,
            filesize: attrs?.filesize,
            checksum: attrs?.checksum,
            platform: attrs?.platform,
            arch: attrs?.arch,
            signature: attrs?.signature,
            status: attrs?.status,
            metadata: attrs?.metadata,
            redirectURL: attrs?.redirectUrl,
            created: attrs?.created,
            updated: attrs?.updated
        )
    }
}

/// The JSON:API `attributes` bag for an artifact resource.
///
/// See `Artifact` for why this declares no `CodingKeys` and why
/// `redirectUrl` is spelled with a lowercase `url` here and `URL` there.
struct ArtifactAttributes: Decodable {
    let filename: String?
    let filetype: String?
    let filesize: Int64?
    let checksum: String?
    let platform: String?
    let arch: String?
    let signature: String?
    let status: String?
    let metadata: [String: JSONValue]?
    let redirectUrl: String?
    let created: Date?
    let updated: Date?

    // No explicit CodingKeys, deliberately. The shared decoder's
    // `.convertFromSnakeCase` leaves every one of this bag's wire names alone
    // (none contains an underscore), and a CodingKey spelled the snake_case way
    // would be compared against the *converted* key and match nothing. See
    // `MachineAttributes`, which shipped that bug.
}

/// A presigned download, and the artifact it belongs to.
///
/// A struct rather than a bare `URL` so a caller can check `artifact.checksum`
/// and `artifact.filesize` against what it actually receives without a second
/// round trip, and so a field can be added later without breaking call sites --
/// the reason `VerifiedLicenseFile` is a struct too.
public struct ArtifactDownload: Equatable, Sendable {
    /// The artifact's metadata, with `redirectURL` populated.
    public let artifact: Artifact

    /// The short-lived presigned storage URL.
    ///
    /// **Fetch this with no credentials and no `Authorization` header.** It
    /// points at object storage rather than the API host and authenticates
    /// itself through its query string, so attaching a credential would hand it
    /// to a host the caller never configured for no benefit.
    ///
    /// **The scheme is validated.** This is the one value in this SDK that is a
    /// URL nobody here chose -- it comes from the response body -- so
    /// `TamgaClient.downloadArtifact(_:ttl:)` rejects anything that is not
    /// `http` or `https` with a host before constructing this, rather than
    /// leaving `URL(string:)` to be mistaken for a guard. It accepts
    /// `file:///etc/passwd`, `javascript:`, `data:` and bare paths, and the
    /// documented next step for this property is to hand it to a downloader.
    /// A caller does not need to re-check the scheme; a caller reading
    /// `Artifact.redirectURL` (the raw string) does.
    ///
    /// It expires. See `TamgaClient.downloadArtifact(_:ttl:)` for the window
    /// and how to widen it.
    public let url: URL
}
