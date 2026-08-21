import Crypto
import Foundation
import Testing

@testable import Tamga

/// Verifying an offline file against a *set* of keys rather than one key.
///
/// The behaviour under test is a discrimination, so almost every case here is
/// a pair: the same failure to verify has to come back as two different errors
/// depending on whether the key the file names is one we hold.
@Suite("Signing-key selection")
struct SigningKeySelectionTests {
    // MARK: - Fixtures

    /// An Ed25519 keypair plus the two forms the SDK deals in: the published
    /// base64 string, and the `TamgaSigningKey` derived from it.
    struct Keypair {
        let privateKey: Curve25519.Signing.PrivateKey
        var publishedPublicKey: String { privateKey.publicKey.rawRepresentation.base64EncodedString() }
        var signingKey: TamgaSigningKey { .ed25519(publicKey: publishedPublicKey) }
        var retiredSigningKey: TamgaSigningKey {
            TamgaSigningKey(
                kid: signingKey.kid, publicKey: publishedPublicKey,
                status: TamgaSigningKey.retiredStatus,
                created: Date(timeIntervalSince1970: 1), retired: Date(timeIntervalSince1970: 2)
            )
        }
        init() { privateKey = Curve25519.Signing.PrivateKey() }
    }

    /// A licence payload carrying a caller-chosen `kid`, so the claim can be
    /// made to agree or disagree with the key that actually signs the file.
    static func licensePayload(kid: String, exp: Int64? = nil) -> Data {
        let expField = exp.map { ",\"exp\":\($0)" } ?? ""
        return Data("""
        {"data":{"id":"lic_123","type":"licenses","attributes":{"key":"K","suspended":false,"uses":0}},\
        "meta":{"iat":1767225600,"jti":"jti-1","kid":"\(kid)"\(expField)}}
        """.utf8)
    }

    /// A plain `.lic` file signed by `signer`, whose payload names `kid`.
    static func plainLicense(signedBy signer: Keypair, claimingKid kid: String? = nil,
                             exp: Int64? = nil) -> String {
        let payload = licensePayload(kid: kid ?? signer.signingKey.kid, exp: exp)
        let enc = CheckoutFixture.plainEnc(json: payload)
        return CheckoutFixture.wrapLicensePEM(
            enc: enc,
            sig: CheckoutFixture.ed25519Sign(enc: enc, privateKey: signer.privateKey),
            alg: "base64+ed25519+v2"
        )
    }

    /// An AES-256-GCM `.lic` file, where the `kid` claim sits inside the
    /// ciphertext and is unreadable without the licence key.
    static func encryptedLicense(signedBy signer: Keypair, licenseKey: String,
                                 claimingKid kid: String? = nil) -> String {
        let payload = licensePayload(kid: kid ?? signer.signingKey.kid)
        let enc = CheckoutFixture.encryptedEnc(
            json: payload, key: Hkdf.deriveLicenseFileKey(licenseKey: licenseKey))
        return CheckoutFixture.wrapLicensePEM(
            enc: enc,
            sig: CheckoutFixture.ed25519Sign(enc: enc, privateKey: signer.privateKey),
            alg: "aes-256-gcm+ed25519+v2"
        )
    }

    static let issuedAt: Int64 = 1_767_225_600

    // MARK: - Rotation: the case that used to look like a forgery

    /// The headline case. A file signed by a key that has since been retired
    /// verifies against the published set, and reports which key it verified
    /// under so the caller can see the file predates the rotation.
    @Test("a file signed before a rotation still verifies, under the retired key")
    func fileSignedByARetiredKeyVerifies() throws {
        let old = Keypair()
        let current = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: old))

        // Newest first, exactly as `list_signing_keys` orders them, so the
        // active key is tried and rejected before the retired one is reached.
        let keys = [current.signingKey, old.retiredSigningKey]

        let verified = try file.verifyWithClaims(signingKeys: keys, licenseKey: "K", now: Self.issuedAt)
        #expect(verified.key.kid == old.signingKey.kid)
        #expect(verified.key.isRetired)
        #expect(verified.claims.kid == old.signingKey.kid)
        #expect(verified.license.id == "lic_123")
    }

    /// The same file against only the current key -- the pre-change behaviour,
    /// kept as a test so the thing being fixed stays visible.
    @Test("against the current key alone, the same file is indistinguishable from a forgery")
    func withoutTheKeySetRotationLooksLikeTampering() throws {
        let old = Keypair()
        let current = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: old))

        let currentOnly = try #require(current.signingKey.publicKeyBytes)
        let rotated = checkoutError {
            _ = try file.verifyWithClaims(publicKey: currentOnly, licenseKey: "K", now: Self.issuedAt)
        }

        let forged = try LicenseFile.parse(
            CheckoutFixture.wrapLicensePEM(
                enc: CheckoutFixture.plainEnc(json: Self.licensePayload(kid: current.signingKey.kid)),
                sig: CheckoutFixture.ed25519Sign(enc: "different-bytes", privateKey: current.privateKey),
                alg: "base64+ed25519+v2"
            )
        )
        let tampered = checkoutError {
            _ = try forged.verifyWithClaims(publicKey: currentOnly, licenseKey: "K", now: Self.issuedAt)
        }

        // Same case, same message, no way to tell them apart.
        #expect(rotated?.caseName == "signatureVerificationFailed")
        #expect(tampered?.caseName == "signatureVerificationFailed")
        #expect(rotated == tampered)
    }

    @Test("a file signed by the active key verifies and reports it as active")
    func fileSignedByTheActiveKeyVerifies() throws {
        let current = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: current))

        let verified = try file.verifyWithClaims(
            signingKeys: [current.signingKey], licenseKey: "K", now: Self.issuedAt)
        #expect(verified.key.isRetired == false)
    }

    // MARK: - The discrimination

    /// A key we do not hold is reported as such, and the reported `kid` is the
    /// signer's real derived id -- not a guess, not the claim of some other key.
    @Test("a file signed by a key outside the set reports that key's id")
    func unknownSigningKeyIsReportedDistinctly() throws {
        let stranger = Keypair()
        let held = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: stranger))

        let error = signingKeyError {
            _ = try file.verifyWithClaims(
                signingKeys: [held.signingKey], licenseKey: "K", now: Self.issuedAt)
        }

        #expect(error == .unknownSigningKey(kid: stranger.signingKey.kid, available: [held.signingKey.kid]))
    }

    /// The other half of the pair: the named key IS in the set, and the
    /// signature still fails. That is tampering, and it keeps the old error --
    /// which now carries information it did not before, because "the key that
    /// signed it is right here" has been ruled in.
    @Test("a tampered file whose named key IS held still reports a failed signature")
    func tamperedFileWithAKnownKidIsNotMistakenForRotation() throws {
        let signer = Keypair()
        let payload = Self.licensePayload(kid: signer.signingKey.kid)
        let enc = CheckoutFixture.plainEnc(json: payload)
        // A signature over different bytes: valid base64, right key, wrong message.
        let file = try LicenseFile.parse(
            CheckoutFixture.wrapLicensePEM(
                enc: enc,
                sig: CheckoutFixture.ed25519Sign(enc: enc + "x", privateKey: signer.privateKey),
                alg: "base64+ed25519+v2"
            )
        )

        let error = checkoutError {
            _ = try file.verifyWithClaims(
                signingKeys: [signer.signingKey], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error?.caseName == "signatureVerificationFailed")
    }

    /// A file that lies about which key signed it, naming one we hold. The
    /// claim is a hint and nothing more, so the lie buys nothing: the signature
    /// still has to pass under a real key, and it does not.
    @Test("a forged file naming a key we hold does not get the rotation error")
    func aForgedKidClaimDoesNotEarnTheRotationError() throws {
        let stranger = Keypair()
        let held = Keypair()
        // Signed by a key we do not have, but claiming the id of one we do.
        let file = try LicenseFile.parse(
            Self.plainLicense(signedBy: stranger, claimingKid: held.signingKey.kid))

        let error = checkoutError {
            _ = try file.verifyWithClaims(
                signingKeys: [held.signingKey], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error?.caseName == "signatureVerificationFailed")
    }

    // MARK: - Unusable key sets

    @Test("an empty key set is its own error, not a verdict about the file")
    func emptyKeySetIsItsOwnError() throws {
        let signer = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: signer))

        let error = signingKeyError {
            _ = try file.verifyWithClaims(signingKeys: [], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error == .noUsableSigningKey(available: []))
    }

    @Test("keys for another algorithm are not tried, and are listed as unusable")
    func nonEd25519KeysAreNotCandidates() throws {
        let signer = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: signer))
        let rsa = TamgaSigningKey(kid: "rsa-kid", algorithm: "rsa2048", publicKey: "AAAA")

        let error = signingKeyError {
            _ = try file.verifyWithClaims(signingKeys: [rsa], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error == .noUsableSigningKey(available: ["rsa-kid"]))
    }

    @Test("a key whose published bytes are not base64 is skipped, not fatal")
    func undecodableKeysAreSkipped() throws {
        let signer = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: signer))
        let broken = TamgaSigningKey(kid: "broken", publicKey: "!!! not base64 !!!")

        // Skipped alongside a good key: verification still succeeds.
        let verified = try file.verifyWithClaims(
            signingKeys: [broken, signer.signingKey], licenseKey: "K", now: Self.issuedAt)
        #expect(verified.key.kid == signer.signingKey.kid)

        // Alone, it leaves nothing to try.
        let error = signingKeyError {
            _ = try file.verifyWithClaims(signingKeys: [broken], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error == .noUsableSigningKey(available: ["broken"]))
    }

    /// A key whose published `kid` disagrees with its own bytes still matches
    /// the claim by its derived id, so a mislabelled key cannot turn a
    /// legitimately-signed file into a reported forgery.
    @Test("a mislabelled key is still matched by its derived id")
    func mislabelledKeyStillMatchesByDerivedId() throws {
        let signer = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: signer))
        let mislabelled = TamgaSigningKey(kid: "0000000000000000", publicKey: signer.publishedPublicKey)

        let verified = try file.verifyWithClaims(
            signingKeys: [mislabelled], licenseKey: "K", now: Self.issuedAt)
        #expect(verified.key.kid == "0000000000000000")
        #expect(verified.key.keyIdIsSelfConsistent == false)
    }

    // MARK: - Ordering: `alg` and expiry are not bypassed

    /// `alg` is checked before any key is looked at, so a file this type cannot
    /// verify at all says so instead of blaming the key set.
    @Test("a bad alg is rejected before key selection, even with no keys")
    func algIsValidatedBeforeKeySelection() throws {
        let signer = Keypair()
        let payload = Self.licensePayload(kid: signer.signingKey.kid)
        let enc = CheckoutFixture.plainEnc(json: payload)
        let file = try LicenseFile.parse(
            CheckoutFixture.wrapLicensePEM(
                enc: enc,
                sig: CheckoutFixture.ed25519Sign(enc: enc, privateKey: signer.privateKey),
                alg: "base64+ed25519"  // pre-v2
            )
        )

        let error = checkoutError {
            _ = try file.verifyWithClaims(signingKeys: [], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error?.caseName == "unsupportedAlgorithm")
    }

    /// Selecting the right key does not excuse an expired file. Authentic and
    /// still valid are separate questions and both are still asked.
    @Test("expiry is still enforced on a file that verifies under a retired key")
    func expiryIsStillEnforcedAfterKeySelection() throws {
        let old = Keypair()
        let expiry = Self.issuedAt + 3600
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: old, exp: expiry))

        let verified = try file.verifyWithClaims(
            signingKeys: [old.retiredSigningKey], licenseKey: "K", now: expiry)
        #expect(verified.claims.exp == expiry)

        let error = checkoutError {
            _ = try file.verifyWithClaims(
                signingKeys: [old.retiredSigningKey], licenseKey: "K", now: expiry + 3600)
        }
        #expect(error?.caseName == "expired")
    }

    // MARK: - Encrypted files

    /// The `kid` of an encrypted file sits inside the ciphertext, so the
    /// classification only works because the licence key is in hand.
    @Test("an encrypted file's kid is still read for classification")
    func encryptedFileClassificationWorks() throws {
        let stranger = Keypair()
        let held = Keypair()
        let file = try LicenseFile.parse(
            Self.encryptedLicense(signedBy: stranger, licenseKey: "LICENCE-KEY-1"))

        let error = signingKeyError {
            _ = try file.verifyWithClaims(
                signingKeys: [held.signingKey], licenseKey: "LICENCE-KEY-1", now: Self.issuedAt)
        }
        #expect(error == .unknownSigningKey(kid: stranger.signingKey.kid, available: [held.signingKey.kid]))
    }

    @Test("an encrypted file signed by a retired key verifies and decrypts")
    func encryptedFileVerifiesUnderARetiredKey() throws {
        let old = Keypair()
        let current = Keypair()
        let file = try LicenseFile.parse(
            Self.encryptedLicense(signedBy: old, licenseKey: "LICENCE-KEY-1"))

        let verified = try file.verifyWithClaims(
            signingKeys: [current.signingKey, old.retiredSigningKey],
            licenseKey: "LICENCE-KEY-1", now: Self.issuedAt)
        #expect(verified.key.kid == old.signingKey.kid)
        #expect(verified.license.key == "K")
    }

    /// Fail closed. With the wrong licence key the `kid` cannot be read at all,
    /// so there is nothing to classify on and the stricter of the two errors is
    /// what comes back.
    @Test("an unreadable kid falls back to a failed signature, never to a guess")
    func anUnreadableKidFailsClosed() throws {
        let stranger = Keypair()
        let held = Keypair()
        let file = try LicenseFile.parse(
            Self.encryptedLicense(signedBy: stranger, licenseKey: "LICENCE-KEY-1"))

        let error = checkoutError {
            _ = try file.verifyWithClaims(
                signingKeys: [held.signingKey], licenseKey: "WRONG-KEY", now: Self.issuedAt)
        }
        #expect(error?.caseName == "signatureVerificationFailed")
    }

    // MARK: - The convenience form

    @Test("verifyAndDecrypt(signingKeys:) returns the licence and enforces expiry")
    func convenienceFormWorks() throws {
        let signer = Keypair()
        let notYetExpired = Int64(Date().timeIntervalSince1970) + 86_400
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: signer, exp: notYetExpired))

        let license = try file.verifyAndDecrypt(signingKeys: [signer.signingKey], licenseKey: "K")
        #expect(license.id == "lic_123")

        let stale = try LicenseFile.parse(
            Self.plainLicense(signedBy: signer, exp: Int64(Date().timeIntervalSince1970) - 86_400))
        let error = checkoutError {
            _ = try stale.verifyAndDecrypt(signingKeys: [signer.signingKey], licenseKey: "K")
        }
        #expect(error?.caseName == "expired")
    }
}

/// Runs `body`, expecting a `TamgaSigningKeyError`, and hands it back so a
/// caller can assert which one -- the mirror of `checkoutError`, and separate
/// from it precisely because the two types are what a caller now discriminates
/// on.
func signingKeyError(
    _ body: () throws -> Void,
    sourceLocation: SourceLocation = #_sourceLocation
) -> TamgaSigningKeyError? {
    do {
        try body()
        Issue.record("expected a TamgaSigningKeyError, but the call succeeded", sourceLocation: sourceLocation)
        return nil
    } catch let error as TamgaSigningKeyError {
        return error
    } catch {
        Issue.record("expected a TamgaSigningKeyError, got \(error)", sourceLocation: sourceLocation)
        return nil
    }
}
