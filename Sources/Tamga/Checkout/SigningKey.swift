import Crypto
import Foundation

/// One public signing key an account has held, current or retired.
///
/// The point of this type is key rotation. An offline `.lic` or `.machine`
/// file carries a `kid` claim inside its signed bytes naming the key that
/// signed it, and the account keeps every key it has ever used
/// (`account_signing_keys`, `signing_keys.rs`). Without the key set, a file
/// signed before a rotation fails against the current key and reports the same
/// `TamgaCheckoutError.signatureVerificationFailed` a forged file does; with
/// it, the two are distinguishable. See
/// `LicenseFile.verifyWithClaims(signingKeys:licenseKey:now:)`.
///
/// **A key set does not have to come from the network.** `TamgaClient`'s
/// `listSigningKeys()` is one source; the memberwise initializer and
/// `ed25519(publicKey:)` are there so a caller can pin keys at build time,
/// load them from a bundled file, or carry them over from a
/// higher-privileged fetch. That matters more than it looks -- see the
/// permission note on `TamgaClient.listSigningKeys()` -- and an offline
/// verifier that can only work while it has a network is not offline.
public struct TamgaSigningKey: Equatable, Sendable {
    /// The `algorithm` value the server writes for every published key today.
    ///
    /// The table's `CHECK` also permits `rsa2048` and `ecdsa_p256`
    /// (`migrations/20240101000032:32-33`), but `rotate_ed25519` is the only
    /// code path that writes a row and it hardcodes `'ed25519'` in both of its
    /// `INSERT`s (`signing_keys.rs:95-99,150-154`). So the published set is
    /// Ed25519-only in practice, and key selection filters on this value
    /// rather than assuming it.
    public static let ed25519Algorithm = "ed25519"

    /// Wire `status` for the key currently signing new files. At most one per
    /// algorithm, enforced by a partial unique index.
    public static let activeStatus = "active"

    /// Wire `status` for a key kept for verification only.
    public static let retiredStatus = "retired"

    /// The key's id -- the JSON:API resource `id`, and the value an offline
    /// file's `kid` claim names.
    ///
    /// The server derives it from `publicKey` by the rule `keyId(forPublicKey:)`
    /// implements, so it is checkable rather than merely trusted; see
    /// `keyIdIsSelfConsistent`.
    public let kid: String

    /// The signing algorithm, e.g. `ed25519`.
    public let algorithm: String

    /// The public key, **exactly as the server publishes it**: standard base64
    /// of the raw key bytes.
    ///
    /// Kept as the published string rather than decoded bytes because the
    /// string is what `kid` hashes. Normalising it -- re-encoding, trimming,
    /// converting to PEM -- changes the hash and breaks the match. Use
    /// `publicKeyBytes` for the decoded form.
    ///
    /// GOTCHA: this is the one camelCase field in an otherwise snake_case
    /// attribute bag (`accounts/serializer.rs:110-111`, an explicit
    /// `#[serde(rename)]`). The shared decoder's snake-case conversion leaves a
    /// key with no underscores alone, so it lands here without a custom
    /// `CodingKeys`, but do not generalise the casing to its neighbours.
    public let publicKey: String

    /// `active` or `retired` (`activeStatus` / `retiredStatus`).
    ///
    /// Deliberately a `String` and not an enum. The column's `CHECK` admits
    /// exactly those two today, but this fleet has been bitten by closed enums
    /// over wire values before, and an unknown future status must not fail a
    /// whole decode.
    public let status: String

    /// When the key was created. Wire name `created`.
    public let created: Date?

    /// When the key was retired, or `nil` while it is active. Wire name
    /// `retired`, and **absent rather than null** when unset -- the server
    /// skips the key entirely (`#[serde(skip_serializing_if = "Option::is_none")]`).
    public let retired: Date?

    /// Creates a key record.
    ///
    /// Public so a caller can supply keys from anywhere -- a pinned constant,
    /// a bundled file, a fetch made with a credential that
    /// `listSigningKeys()` needs and an embedded client does not have.
    public init(
        kid: String,
        algorithm: String = TamgaSigningKey.ed25519Algorithm,
        publicKey: String,
        status: String = TamgaSigningKey.activeStatus,
        created: Date? = nil,
        retired: Date? = nil
    ) {
        self.kid = kid
        self.algorithm = algorithm
        self.publicKey = publicKey
        self.status = status
        self.created = created
        self.retired = retired
    }

    /// Builds an Ed25519 key record from the published public key alone,
    /// deriving `kid` locally.
    ///
    /// The intended way to pin a key: a caller who has the public key does not
    /// also need to be told its id, because the id is a function of the key.
    public static func ed25519(publicKey: String, status: String = TamgaSigningKey.activeStatus)
        -> TamgaSigningKey {
        TamgaSigningKey(
            kid: keyId(forPublicKey: publicKey),
            algorithm: ed25519Algorithm,
            publicKey: publicKey,
            status: status
        )
    }

    /// The stable short id of a public key: the first **eight bytes** of
    /// `SHA-256` over the public key **string**, lowercase hex -- sixteen hex
    /// characters.
    ///
    /// Mirrors the server's `key_id` (`shared/crypto/license_file.rs:70-77`)
    /// exactly, and the two details most easily got wrong are both visible in
    /// that signature:
    ///
    /// - The hash covers the **base64 string's UTF-8 bytes**, not the decoded
    ///   key bytes. `key_id(ed25519_public_key: &str)` takes `&str` and calls
    ///   `.as_bytes()` on it.
    /// - Eight *bytes*, sixteen hex characters -- not eight characters.
    ///
    /// Verified against the twelve server-generated machine-file fixtures:
    /// every one of their `kid` values reproduces from its own
    /// `public_key_b64` under this rule, across all four signing schemes
    /// (`SigningKeyTests.keyIdMatchesEveryServerFixture`).
    public static func keyId(forPublicKey publicKey: String) -> String {
        SHA256.hash(data: Data(publicKey.utf8))
            .prefix(8)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    /// This key's id as computed locally from `publicKey`.
    public var computedKeyId: String { Self.keyId(forPublicKey: publicKey) }

    /// Whether the server-published `kid` matches the one derived from
    /// `publicKey`.
    ///
    /// A `false` here is worth reporting upstream; it is not something a client
    /// can fix. **It does not affect whether files verify.**
    ///
    /// The previous wording here said key selection matches on *either* id "so
    /// a server that ever labelled a key inconsistently would not silently lose
    /// the ability to verify files signed with it". The first half is true and
    /// the second does not follow, so it is corrected rather than kept.
    /// `SigningKeySelection.resolve` tries every candidate against the
    /// signature *before* reading any `kid`, and returns on the first that
    /// passes -- so a mislabelled key verifies a genuine file without the claim
    /// being consulted at all, and would do so under a served-id-only rule too.
    /// The ability to verify never depended on the match.
    ///
    /// What the either-match does decide is one error label, on a path where
    /// every key has already failed: whether a file whose claim names the
    /// *derived* id of a mislabelled key we hold reports
    /// `TamgaCheckoutError.signatureVerificationFailed` ("the key it names is
    /// right here and the signature is still bad") or
    /// `TamgaSigningKeyError.unknownSigningKey` ("fetch the key set again").
    /// The rest of this SDK fleet matches the served id only and reports the
    /// served/computed disagreement as its own condition -- which is exactly
    /// what this property is. Measured, not assumed: narrowing the match to the
    /// served id leaves every test in this package green except the one written
    /// to pin this distinction
    /// (`SigningKeyIdLenienceTests.derivedIdMatchOnlyPicksAnErrorLabel`).
    public var keyIdIsSelfConsistent: Bool { computedKeyId == kid }

    /// The decoded public key bytes, or `nil` if `publicKey` is not valid
    /// base64.
    ///
    /// For Ed25519 this is the raw 32-byte key, which is what
    /// `LicenseFile.verify(publicKey:)` and `MachineFile`'s Ed25519 branch
    /// expect.
    public var publicKeyBytes: Data? { Data(base64Encoded: publicKey) }

    /// Whether this key is retired -- verification only, no longer signing.
    public var isRetired: Bool { status == Self.retiredStatus }
}

/// Failures specific to selecting a signing key for an offline file.
///
/// **A separate type, deliberately, and not a new `TamgaCheckoutError` case.**
/// `TamgaCheckoutError` is a plain public enum in a package built from source,
/// so adding a case to it breaks every exhaustive `switch` a consumer has
/// written, at compile time, on a minor version a `from:` requirement upgrades
/// into automatically. The distinction this round exists to draw does not need
/// to live in that enum: it is only reachable through the key-set entry points
/// added alongside it, which are new surface and can therefore throw a new
/// type without breaking anything that compiles today.
///
/// Callers already switching on `TamgaCheckoutError` keep working unchanged.
/// Callers using the new entry points catch this alongside it:
///
/// ```swift
/// do {
///     let license = try file.verifyAndDecrypt(signingKeys: keys, licenseKey: key)
/// } catch let error as TamgaSigningKeyError {
///     // The file is not verifiable with the keys I have -- refresh the set.
/// } catch TamgaCheckoutError.signatureVerificationFailed {
///     // The key that signed it IS in the set, and it still does not verify.
///     // This one is forged or corrupted.
/// }
/// ```
public enum TamgaSigningKeyError: Error, Equatable {
    /// The key set held nothing that could verify anything: it was empty, or
    /// every entry was for another algorithm, or none decoded as base64.
    ///
    /// **An empty set is the ordinary state of a healthy account**, not an
    /// error condition upstream. `account_signing_keys` is written only by
    /// `rotate_ed25519` (`signing_keys.rs:113-`), which backfills the current
    /// key on its way through, so an account that has never rotated has no
    /// rows at all and `GET /signing-keys` answers `{"data": []}`. Pin the
    /// account's published key with `TamgaSigningKey.ed25519(publicKey:)` and
    /// verification works before the first rotation as well as after it.
    ///
    /// The associated value lists the ids that were present but unusable.
    case noUsableSigningKey(available: [String])

    /// No key in the set verified the file, and the file's own `kid` claim
    /// names a key the set does not contain.
    ///
    /// **This is the case that is not a forgery.** The file says which key
    /// signed it, and that key is simply absent -- a set fetched before the
    /// last rotation, a pinned key that has since been superseded, or a key an
    /// operator deleted outright (which is how a *compromised* key is retired,
    /// and which does invalidate every legitimate file signed with it). Fetch
    /// the key set again before treating the file as suspect.
    ///
    /// The `kid` is read from the file's payload **after** every known key has
    /// failed, and is used only to pick between this error and
    /// `TamgaCheckoutError.signatureVerificationFailed`. It is unverified
    /// input: nothing else is derived from it, and no `License` or `Machine`
    /// is ever produced from an unverified payload.
    case unknownSigningKey(kid: String, available: [String])

    /// The file cannot be matched to a key by `kid`, because for this signing
    /// scheme the `kid` does not name the key that signed the file.
    ///
    /// **This is a server property, not a client limitation.** Both checkout
    /// handlers compute the claim as
    /// `key_id(account.ed25519_public_key.unwrap_or_default())`
    /// unconditionally (`check_out_license.rs:92-94`,
    /// `check_out_machine.rs:125-127`), while a machine file's *signing* key is
    /// chosen by the licence's scheme (`check_out_machine.rs:83-96`). For an
    /// RSA- or ECDSA-signed machine file the two are different keys, so the
    /// `kid` names an Ed25519 key that had no part in the signature -- and
    /// `/signing-keys` publishes Ed25519 keys only anyway.
    ///
    /// Licence files are unaffected: they are always Ed25519-signed, so their
    /// `kid` always names their signing key.
    ///
    /// Verify these with `MachineFile.verifyWithClaims(scheme:publicKey:...)`
    /// and the account's own public key for that algorithm. Rotation via
    /// `/actions/rotate-signing-key` only ever rotates the Ed25519 key, so
    /// there is no rotation for these schemes to survive today.
    case keyIdNotApplicable(scheme: String)
}

extension TamgaSigningKeyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noUsableSigningKey(let available):
            return "No usable Ed25519 signing key was supplied"
                + (available.isEmpty ? " (the key set was empty)." : " (had: \(available.joined(separator: ", "))).")
        case .unknownSigningKey(let kid, let available):
            return "The file is signed by key '\(kid)', which is not in the key set"
                + (available.isEmpty ? "." : " (had: \(available.joined(separator: ", "))).")
        case .keyIdNotApplicable(let scheme):
            return "A \(scheme) machine file's 'kid' claim names the account's Ed25519 key, "
                + "not the key that signed it, so it cannot be matched against a key set."
        }
    }
}
