import Foundation

/// Reading and downloading release artifacts.
///
/// ## Why this only appeared now
///
/// Precisely one of these three routes was blocked, and it is worth stating
/// exactly which. `artifact.read` has been in `Role::LicenseToken` all along
/// (`shared/authz/mod.rs:264`), so list and show were always reachable -- this
/// SDK simply had not wrapped them. `artifact.download` was in **no** role's
/// default list, and `effective_permissions` intersects the bearer's set with
/// the token's while taking the bearer side solely from
/// `role.default_permissions()`, so granting the token the action could not
/// rescue it either. `download_artifact` also had no route at all.
/// `tamga-api@e6d317b` adds the single line `artifact.download`
/// (`shared/authz/mod.rs:265`) and routes the handler.
///
/// Still absent from `Role::LicenseToken`: `artifact.create`, `artifact.update`
/// and `artifact.delete`. Publishing is an operator action, not a client one,
/// and this SDK wraps no write here.
extension TamgaClient {
    /// Lists a release's artifacts, one keyset-paginated page at a time.
    ///
    /// Keyset like `listComponents`, not offset like `listMachines`: the route
    /// reports no `meta.page`, so the cursor is synthesized from page fullness
    /// the same way. The synthesis is sound here -- the query really does order
    /// by `(created_at, id)` and seek past the cursor row
    /// (`artifacts/queries.rs`), which is what `listEntitlements` cannot claim.
    ///
    /// Requires `artifact.read`, which a licence token now holds.
    ///
    /// **This route does not apply the owning release's read gate**, unlike
    /// `downloadArtifact(_:ttl:)`. `list_artifacts` calls `require_read` and
    /// nothing else, so a CLOSED release's artifact *metadata* is listable by
    /// any caller holding `artifact.read` even though its bytes are not
    /// reachable. Do not infer downloadability from a successful listing.
    public func listReleaseArtifacts(
        releaseId: String,
        options: ListOptions = ListOptions()
    ) async throws -> Page<Artifact> {
        let data = try await transport.getJSON(["releases", releaseId, "artifacts"],
                                               query: Self.pageQuery(options))
        let envelope = try Self.decode(ListEnvelope<ArtifactAttributes>.self, from: data)
        return Page(nextCursor: Self.synthesizeCursor(envelope.data, options: options),
                    items: envelope.data.map(Artifact.fromResource))
    }

    /// Fetches one artifact's metadata by id.
    ///
    /// `redirectURL` is **always** `nil` on this response -- the server skips
    /// the key on show. Use `downloadArtifact(_:ttl:)` to get a URL.
    ///
    /// Note the path shape: artifacts are addressed directly under the account,
    /// not nested under their release, even though listing them is nested.
    public func getArtifact(_ artifactId: String) async throws -> Artifact {
        let data = try await transport.getJSON(["artifacts", artifactId])
        return Artifact.fromResource(
            try Self.decode(DataEnvelope<ArtifactAttributes>.self, from: data).data)
    }

    /// Asks for a short-lived presigned URL for an artifact's bytes.
    ///
    /// ## This deliberately does not follow the redirect, and does not download
    ///
    /// The route's default answer is a `303 See Other` pointing at object
    /// storage. Following it with this client's `Authorization` header still
    /// attached would hand the licence key to the storage host -- so this SDK
    /// refuses redirects outright at the `URLSession` layer
    /// (`SessionPolicyDelegate.urlSession(_:task:willPerformHTTPRedirection:…)`
    /// answers `completionHandler(nil)`), and a `303` reaching that layer would
    /// surface as `TamgaError.api` with `httpStatus == 303` rather than being
    /// followed.
    ///
    /// Rather than work around that, this asks for `?redirect=false`, which
    /// returns the artifact resource with `redirectUrl` populated and no `3xx`
    /// at all. The URL comes back for the caller to fetch **with no
    /// credentials**: it authenticates itself through its query string, and a
    /// real artifact is routinely larger than this client's 32 MiB response cap
    /// anyway, so streaming it through `Transport` would be wrong even if it
    /// were safe.
    ///
    /// ```swift
    /// let download = try await client.downloadArtifact(artifactId)
    /// // A plain session. NOT the SDK's client, and no Authorization header.
    /// let (localURL, _) = try await URLSession.shared.download(from: download.url)
    /// ```
    ///
    /// ## A `403` here is not necessarily an auth misconfiguration
    ///
    /// The handler enforces the owning release's read gate as well as the
    /// permission (`releases::service::enforce_release_access`), because an
    /// artifact is the payload of the release that owns it. Four separate
    /// conditions answer `403`, and holding `artifact.download` does not
    /// satisfy any of them:
    ///
    /// - the product's **distribution strategy** (a `CLOSED` product admits
    ///   only admin, developer and product tokens);
    /// - the licence is **suspended**;
    /// - the licence is **expired** and its policy's `expirationStrategy`
    ///   stops it receiving builds published after its expiry;
    /// - the licence is **not entitled** to that release.
    ///
    /// So do not read a `403` as "the SDK is missing a permission". Before
    /// `tamga-api@e6d317b` it always was; now it usually is not.
    ///
    /// - Parameters:
    ///   - artifactId: The artifact's id.
    ///   - ttl: How long the URL should stay valid, in seconds. `nil` accepts
    ///     the server's default of 300s. The server validates rather than
    ///     clamps, so an out-of-range value is `422 PRESIGN_TTL_INVALID`
    ///     (`artifacts/service.rs:30-38`); this checks the same range first so
    ///     the round trip is not wasted.
    /// - Throws: `TamgaError.transport` before any request when `ttl` is
    ///   outside `minimumDownloadTTLSeconds...maximumDownloadTTLSeconds`;
    ///   `TamgaError.malformedResponse` when the response carries no usable
    ///   `redirectUrl`; `TamgaError.api` otherwise, notably
    ///   `422 STORAGE_UNAVAILABLE` when the deployment has no object storage
    ///   configured at all.
    public func downloadArtifact(
        _ artifactId: String,
        ttl: Int? = nil
    ) async throws -> ArtifactDownload {
        var query = [
            // Always false, never caller-controlled. `true` would produce a
            // `303` this client refuses by design; exposing the choice would
            // only let a caller ask for a failure.
            URLQueryItem(name: "redirect", value: "false")
        ]
        if let ttl {
            guard (Self.minimumDownloadTTLSeconds...Self.maximumDownloadTTLSeconds).contains(ttl)
            else {
                throw TamgaError.transport(
                    message: "A download URL's ttl must be between "
                        + "\(Self.minimumDownloadTTLSeconds) and "
                        + "\(Self.maximumDownloadTTLSeconds) seconds; \(ttl) was requested.",
                    underlying: nil)
            }
            query.append(URLQueryItem(name: "ttl", value: String(ttl)))
        }

        let data = try await transport.getJSON(
            ["artifacts", artifactId, "actions", "download"], query: query)
        let artifact = Artifact.fromResource(
            try Self.decode(DataEnvelope<ArtifactAttributes>.self, from: data).data)

        // A 2xx with no `redirectUrl` means the server took a path this call
        // did not ask for. Returning an `Artifact` with a nil URL would push
        // that ambiguity onto every call site.
        guard let redirect = artifact.redirectURL, let url = URL(string: redirect) else {
            throw TamgaError.malformedResponse(
                message: "The download response carried no usable redirectUrl.", underlying: nil)
        }
        return ArtifactDownload(artifact: artifact, url: url)
    }

    /// Shortest presigned-URL lifetime the server accepts, in seconds.
    /// Mirrors `PRESIGN_TTL_MIN` (`artifacts/service.rs:15`).
    public static let minimumDownloadTTLSeconds = 60

    /// Longest presigned-URL lifetime the server accepts, in seconds -- one
    /// week. Mirrors `PRESIGN_TTL_MAX` (`artifacts/service.rs:17`).
    public static let maximumDownloadTTLSeconds = 604_800
}
