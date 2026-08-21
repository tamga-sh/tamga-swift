import Foundation

/// Picks the signing key an offline file was actually signed with, out of the
/// set of keys the account has held.
///
/// ## Order, and why it is this way round
///
/// The obvious implementation reads the file's `kid` claim first and uses it
/// to look a key up. That inverts the one ordering rule the rest of this
/// directory is built on -- verify the signature before interpreting anything
/// inside `enc` -- because the claim lives *inside* the signed (and possibly
/// encrypted) payload, so reading it means parsing attacker-supplied bytes
/// before anything has vouched for them.
///
/// So this does the opposite. Every candidate key is tried against the
/// signature first, and the happy path never touches the payload
/// unverified. The claim is read only after every key has failed -- at which
/// point the file is already known not to be authentic under any key we hold,
/// and the only remaining question is which of two errors to report. Its
/// value picks an error label and is used for nothing else.
///
/// The cost is at most one signature check per key the account has ever held,
/// which for Ed25519 is microseconds and for a realistic key set is a handful
/// of them. `kid` is an unauthenticated hint in JWS too, for the same reason:
/// it selects a key from a trusted set, it never establishes trust.
enum SigningKeySelection {
    /// The key that verified, together with its decoded public key bytes.
    struct Match {
        let key: TamgaSigningKey
        let publicKey: Data
    }

    /// - Parameters:
    ///   - keys: the account's key set, in any order.
    ///   - verify: runs the file's signature check against one candidate's
    ///     decoded public key. Must not throw: `alg` validation belongs before
    ///     this call, not once per key.
    ///   - unverifiedKeyId: reads the file's own `kid` claim without verifying
    ///     it. Called at most once, and only after every candidate has failed.
    static func resolve(
        keys: [TamgaSigningKey],
        verify: (Data) -> Bool,
        unverifiedKeyId: () -> String?
    ) throws -> Match {
        // An entry for another algorithm cannot verify an Ed25519 signature and
        // is dropped rather than tried, so the diagnostics below say "no usable
        // key" instead of "unknown key" when a set is present but irrelevant.
        let candidates = keys.compactMap { key -> Match? in
            guard key.algorithm == TamgaSigningKey.ed25519Algorithm,
                  let bytes = key.publicKeyBytes else { return nil }
            return Match(key: key, publicKey: bytes)
        }

        guard !candidates.isEmpty else {
            throw TamgaSigningKeyError.noUsableSigningKey(available: keys.map(\.kid))
        }

        for candidate in candidates where verify(candidate.publicKey) {
            return candidate
        }

        let available = candidates.map(\.key.kid)

        // Nothing verified. Only now is the payload worth looking at, and only
        // for the one field that separates the two failures.
        guard let claimed = unverifiedKeyId() else {
            throw TamgaCheckoutError.signatureVerificationFailed
        }

        // Match on the published id OR the locally derived one.
        //
        // Scope, because the obvious reading overstates it: this cannot decide
        // whether anything verifies. Every candidate was already tried against
        // the signature above and every one failed, so all that is left is
        // which of two errors to report. A file legitimately signed by a
        // mislabelled key returns from the loop above without any `kid` being
        // read -- the lenient match is not what rescued it, and narrowing this
        // to the served id would not endanger it.
        //
        // The rest of the fleet matches the served id only and surfaces a
        // served/computed disagreement through the equivalent of
        // `TamgaSigningKey.keyIdIsSelfConsistent` instead. Kept lenient here
        // because on the one input where the two differ -- a file claiming the
        // derived id of a mislabelled key the account really does hold -- "the
        // key it names is right here and the signature is still bad" is the
        // more accurate of the two labels, and changing an error label is a
        // behaviour change this port has no reason to make on a patch. See
        // `SigningKeyIdLenienceTests.derivedIdMatchOnlyPicksAnErrorLabel`,
        // which is the only test in the package that tells the two rules
        // apart.
        let named = candidates.contains {
            $0.key.kid == claimed || $0.key.computedKeyId == claimed
        }
        if named {
            // The key it names is right here and the signature still fails.
            // That is tampering, not rotation.
            throw TamgaCheckoutError.signatureVerificationFailed
        }
        throw TamgaSigningKeyError.unknownSigningKey(kid: claimed, available: available)
    }
}

/// A licence file that verified, and the key it verified under.
///
/// A struct rather than a tuple, and not only because SwiftLint dislikes
/// three-element tuples: a tuple's shape *is* its type, so gaining a field
/// later would break every call site, while a struct can gain one silently.
/// On a package whose consumers resolve `from:` and upgrade into minors
/// automatically, that difference decides whether the next addition here is
/// shippable without a major.
public struct VerifiedLicenseFile: Sendable {
    /// The decoded licence.
    public let license: License
    /// The claims carried inside the signed bytes.
    public let claims: LicenseFileClaims
    /// The key the signature verified under.
    ///
    /// Worth inspecting: `key.isRetired` means the file is authentic and was
    /// issued before the account's last rotation. Nothing is wrong with it,
    /// but whatever hands these out is due a fresh checkout.
    public let key: TamgaSigningKey
}

/// A machine file that verified, and the key it verified under. See
/// `VerifiedLicenseFile` for why this is a struct.
public struct VerifiedMachineFile: Sendable {
    /// The decoded machine.
    public let machine: Machine
    /// The claims carried inside the signed bytes.
    public let claims: LicenseFileClaims
    /// The key the signature verified under.
    public let key: TamgaSigningKey
}

// MARK: - License files

extension LicenseFile {
    /// Verifies against a key set rather than a single key, so a file signed
    /// before a key rotation still verifies -- and a file signed by a key the
    /// set does not contain is reported as such instead of as a forgery.
    ///
    /// Licence files are always Ed25519-signed and their `kid` always names
    /// their signing key (`check_out_license.rs:92-94` hashes the same
    /// `account.ed25519_public_key` the file was signed with), so this applies
    /// to every `.lic` file without qualification. The machine-file
    /// counterpart carries a caveat; see
    /// `MachineFile.verifyWithClaims(signingKeys:scheme:licenseKey:fingerprint:now:)`.
    ///
    /// Everything else matches
    /// `verifyWithClaims(publicKey:licenseKey:now:)`: the signature must pass,
    /// the payload is decrypted or plain-decoded, and the signed `exp` claim is
    /// enforced against `now`. The key that verified comes back too, so a
    /// caller can tell an active key from a retired one -- a file that only
    /// verifies under a retired key is authentic, and is also a signal that
    /// whatever issued it is overdue for a fresh checkout.
    ///
    /// - Throws: `TamgaSigningKeyError.unknownSigningKey` when the file names a
    ///   key the set does not hold, `TamgaSigningKeyError.noUsableSigningKey`
    ///   when the set holds no usable Ed25519 key at all, and otherwise exactly
    ///   what `verifyWithClaims(publicKey:licenseKey:now:)` throws --
    ///   `.signatureVerificationFailed` here really does mean the named key is
    ///   present and the signature is bad.
    public func verifyWithClaims(
        signingKeys: [TamgaSigningKey],
        licenseKey: String,
        now: Int64
    ) throws -> VerifiedLicenseFile {
        try validateAlgorithm()

        let match = try SigningKeySelection.resolve(
            keys: signingKeys,
            // `validateAlgorithm` above is the only thing `verify` throws for,
            // and it has already passed, so this cannot swallow a real error.
            verify: { (try? verify(publicKey: $0)) == true },
            unverifiedKeyId: { unverifiedClaims(licenseKey: licenseKey)?.kid }
        )

        let verified = try verifyWithClaims(
            publicKey: match.publicKey, licenseKey: licenseKey, now: now)
        return VerifiedLicenseFile(
            license: verified.license, claims: verified.claims, key: match.key)
    }

    /// As `verifyWithClaims(signingKeys:licenseKey:now:)`, taking the current
    /// time from the system clock and returning only the licence.
    ///
    /// Prefer the claims-returning form where a trusted timestamp is
    /// available: on an offline path the local clock is under the attacker's
    /// control by definition.
    public func verifyAndDecrypt(
        signingKeys: [TamgaSigningKey],
        licenseKey: String
    ) throws -> License {
        try verifyWithClaims(
            signingKeys: signingKeys,
            licenseKey: licenseKey,
            now: Int64(Date().timeIntervalSince1970)
        ).license
    }
}

// MARK: - Machine files

extension MachineFile {
    /// Verifies against a key set rather than a single key. **Ed25519-signed
    /// machine files only.**
    ///
    /// The restriction is the server's, not this SDK's, and it is worth
    /// stating precisely because the natural assumption is wrong. A machine
    /// file's signing key is chosen by the licence's scheme
    /// (`check_out_machine.rs:83-96`), but its `kid` claim is computed from
    /// `account.ed25519_public_key` **whatever the scheme**
    /// (`check_out_machine.rs:125-127`). For an RSA- or ECDSA-signed file the
    /// claim therefore names a key that did not sign it, and `/signing-keys`
    /// publishes Ed25519 keys only in any case
    /// (`signing_keys.rs:95-99,150-154`). Those files get
    /// `TamgaSigningKeyError.keyIdNotApplicable` here and must be verified with
    /// `verifyWithClaims(scheme:publicKey:licenseKey:fingerprint:now:)` and the
    /// account's own key for that algorithm. Nothing is lost by it:
    /// `/actions/rotate-signing-key` rotates the Ed25519 key alone, so no other
    /// scheme has a rotation to survive.
    ///
    /// A `.none` scheme is accepted, matching the server's own default of
    /// Ed25519 for an unset scheme (`check_out_machine.rs:68-73`).
    ///
    /// - Throws: `TamgaSigningKeyError.keyIdNotApplicable` for a
    ///   non-Ed25519 scheme, plus everything
    ///   `LicenseFile.verifyWithClaims(signingKeys:licenseKey:now:)` throws and
    ///   everything `verifyWithClaims(scheme:publicKey:licenseKey:fingerprint:now:)`
    ///   throws.
    public func verifyWithClaims(
        signingKeys: [TamgaSigningKey],
        scheme: LicenseScheme,
        licenseKey: String,
        fingerprint: String,
        now: Int64
    ) throws -> VerifiedMachineFile {
        guard scheme == .ed25519Sign || scheme == .none else {
            throw TamgaSigningKeyError.keyIdNotApplicable(scheme: scheme.rawValue)
        }

        let algorithm = try validatedAlgorithm(scheme: scheme)

        let match = try SigningKeySelection.resolve(
            keys: signingKeys,
            verify: { verifySignature(scheme: scheme, publicKey: $0) },
            unverifiedKeyId: {
                unverifiedClaims(
                    algorithm: algorithm, licenseKey: licenseKey, fingerprint: fingerprint
                )?.kid
            }
        )

        let verified = try verifyWithClaims(
            scheme: scheme,
            publicKey: match.publicKey,
            licenseKey: licenseKey,
            fingerprint: fingerprint,
            now: now
        )
        return VerifiedMachineFile(
            machine: verified.machine, claims: verified.claims, key: match.key)
    }

    /// As `verifyWithClaims(signingKeys:scheme:licenseKey:fingerprint:now:)`,
    /// taking the current time from the system clock and returning only the
    /// machine.
    public func verifyAndDecrypt(
        signingKeys: [TamgaSigningKey],
        scheme: LicenseScheme,
        licenseKey: String,
        fingerprint: String
    ) throws -> Machine {
        try verifyWithClaims(
            signingKeys: signingKeys,
            scheme: scheme,
            licenseKey: licenseKey,
            fingerprint: fingerprint,
            now: Int64(Date().timeIntervalSince1970)
        ).machine
    }
}
