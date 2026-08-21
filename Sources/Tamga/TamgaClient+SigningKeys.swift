import Foundation

/// The account's published signing keys.
extension TamgaClient {
    /// Reads `GET /v1/accounts/{accountId}/signing-keys`.
    ///
    /// Every key the account has held, current and retired, newest first
    /// (`ORDER BY created_at DESC, kid ASC` -- `signing_keys.rs:56-62`).
    /// Retired keys are included by design: a client holding a file signed
    /// before the last rotation needs the key that signed it, and its only
    /// other options are to fail verification or to accept any key, the second
    /// of which defeats signing entirely.
    ///
    /// Only public halves come back. `PublishedSigningKey` has no field for a
    /// private key, so one cannot leak through this route even if the query
    /// were changed to select it.
    ///
    /// **Not reachable with a licence-key credential.** The route requires
    /// `account.read` (`accounts/policy.rs:16-18`), and
    /// `Role::LicenseToken` -- what a `License`/`Basic license:` credential
    /// resolves to (`shared/auth/context.rs:43`,
    /// `shared/auth/license_lookup.rs:90`) -- does not hold it
    /// (`shared/authz/mod.rs:236-261`). An embedded client authenticating with
    /// a licence key gets `403`. There is no second route that returns the same
    /// resource under a permission it does hold, unlike `getPolicy(_:)` and
    /// `getLicensePolicy(_:)`.
    ///
    /// That is not fatal to key rotation, because a key set does not have to
    /// arrive over the wire: build `TamgaSigningKey.ed25519(publicKey:)` values
    /// from keys pinned into the app, or fetched by a build step or a server of
    /// your own using an admin token, and pass those to
    /// `LicenseFile.verifyWithClaims(signingKeys:licenseKey:now:)`. An offline
    /// verifier that only works while it has a network is not offline.
    ///
    /// **An empty result is normal, not an error.** `account_signing_keys` is
    /// written only by `rotate_ed25519`, which backfills the account's current
    /// key on its way through (`signing_keys.rs:113-`), so an account that has
    /// never rotated has no rows and this returns `[]`. Pin the account's
    /// published key rather than treating an empty set as a failure.
    ///
    /// `algorithm` is `ed25519` on every row today: the table's `CHECK` also
    /// admits `rsa2048` and `ecdsa_p256`, but nothing writes them.
    public func listSigningKeys() async throws -> [TamgaSigningKey] {
        let data = try await transport.getJSON(["signing-keys"])
        let envelope = try Self.decode(ListEnvelope<SigningKeyAttributes>.self, from: data)
        return envelope.data.map(TamgaSigningKey.fromResource)
    }
}

/// The JSON:API `attributes` bag for a signing-key resource.
///
/// Snake_case struct with exactly one camelCase field: `public_key` is renamed
/// to `publicKey` (`accounts/serializer.rs:108-111`) and nothing else in the
/// bag is. The shared decoder's `convertFromSnakeCase` leaves a key with no
/// underscore in it untouched, so both spellings land on `publicKey` and no
/// per-type `CodingKeys` is needed -- but do not generalise the casing.
///
/// Every field is optional here even though the server declares them
/// non-optional, so one unexpected omission degrades to `nil` rather than
/// failing the whole list decode.
struct SigningKeyAttributes: Decodable {
    let algorithm: String?
    let publicKey: String?
    let status: String?
    let created: Date?
    let retired: Date?
}

extension TamgaSigningKey {
    /// The resource `id` is the `kid` -- `SigningKeyResource` sets
    /// `id: k.kid` (`accounts/serializer.rs:119-122`), which is why an offline
    /// file's claim can be matched straight against it.
    static func fromResource(_ resource: JSONAPIResource<SigningKeyAttributes>) -> TamgaSigningKey {
        let attrs = resource.attributes
        return TamgaSigningKey(
            kid: resource.id,
            algorithm: attrs?.algorithm ?? TamgaSigningKey.ed25519Algorithm,
            publicKey: attrs?.publicKey ?? "",
            status: attrs?.status ?? TamgaSigningKey.activeStatus,
            created: attrs?.created,
            retired: attrs?.retired
        )
    }
}
