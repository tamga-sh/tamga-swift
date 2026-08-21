import Crypto
import Foundation
import Testing

@testable import Tamga

/// What matching a file's `kid` claim on the **derived** id as well as the
/// **served** one actually decides -- which turns out to be much less than the
/// name suggests.
///
/// Split out of `SigningKeySelectionTests` when that file passed the 400-line
/// limit, and cohesive on its own: every case here is about the lookup on the
/// already-failed path, not about selection succeeding.
///
/// The rest of this SDK fleet matches the served id only. That difference is
/// unobservable in this port except through one error label, because
/// `SigningKeySelection.resolve` tries every candidate against the signature
/// before reading any claim. Narrowing the match to the served id leaves every
/// other test in this package green -- measured, and the reason the fix for the
/// divergence was the documentation rather than the code.
@Suite("Signing-key id lenience")
struct SigningKeyIdLenienceTests {
    typealias Keypair = SigningKeySelectionTests.Keypair

    static func plainLicense(signedBy signer: Keypair, claimingKid kid: String? = nil) -> String {
        SigningKeySelectionTests.plainLicense(signedBy: signer, claimingKid: kid)
    }

    static let issuedAt = SigningKeySelectionTests.issuedAt

    /// A file signed by a mislabelled key verifies, and -- the part the old
    /// name for this test got wrong -- **not because of the derived-id match**.
    /// No `kid` is consulted at all on this path. `SigningKeySelection.resolve`
    /// tries every candidate against the signature first and returns on the
    /// first that passes, so the claim is never read. Mutating the lookup to
    /// the served id alone leaves this green.
    @Test("a mislabelled key verifies a genuine file without any kid being read")
    func mislabelledKeyVerifiesWithoutConsultingTheClaim() throws {
        let signer = Keypair()
        let file = try LicenseFile.parse(Self.plainLicense(signedBy: signer))
        let mislabelled = TamgaSigningKey(kid: "0000000000000000", publicKey: signer.publishedPublicKey)

        let verified = try file.verifyWithClaims(
            signingKeys: [mislabelled], licenseKey: "K", now: Self.issuedAt)
        #expect(verified.key.kid == "0000000000000000")
        #expect(verified.key.keyIdIsSelfConsistent == false)

        // And the same holds when the claim names something no key answers to,
        // which would be an `unknownSigningKey` if the claim were consulted.
        let claimingNothing = try LicenseFile.parse(
            Self.plainLicense(signedBy: signer, claimingKid: "ffffffffffffffff"))
        let stillVerifies = try claimingNothing.verifyWithClaims(
            signingKeys: [mislabelled], licenseKey: "K", now: Self.issuedAt)
        #expect(stillVerifies.key.kid == "0000000000000000")
    }

    /// The one thing the derived-id match actually decides, isolated.
    ///
    /// It is reachable only once every key has already failed the signature
    /// check, so it cannot make a genuine file verify or fail. All it picks is
    /// which of two errors names the failure -- and it only differs from the
    /// served-id rule the rest of the fleet uses when the account has published
    /// a key whose `kid` disagrees with its own bytes AND the file's claim
    /// names the derived id rather than the published one.
    @Test("the derived-id match decides an error label, never whether a file verifies")
    func derivedIdMatchOnlyPicksAnErrorLabel() throws {
        let signer = Keypair()
        let other = Keypair()

        // A key we hold, published under a `kid` that is not its own hash.
        let mislabelled = TamgaSigningKey(kid: "0000000000000000",
                                          publicKey: signer.publishedPublicKey)
        let derivedId = mislabelled.computedKeyId
        #expect(derivedId != mislabelled.kid)

        // A file that does NOT verify under it, whose claim names the derived
        // id. Signed by `other`, so no key in the set can verify it.
        let forged = try LicenseFile.parse(
            Self.plainLicense(signedBy: other, claimingKid: derivedId))

        // Lenient (this port): the key it names is one we hold, so this is
        // tampering rather than a rotation we missed.
        let error = checkoutError {
            _ = try forged.verifyWithClaims(
                signingKeys: [mislabelled], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error?.caseName == "signatureVerificationFailed")

        // Under the served-id-only rule the same file would report
        // `unknownSigningKey(kid: derivedId, ...)` instead. Either way it does
        // not verify, which is the point: the choice cannot admit a forgery or
        // reject a genuine file.
        let genuine = try LicenseFile.parse(
            Self.plainLicense(signedBy: signer, claimingKid: derivedId))
        let verified = try genuine.verifyWithClaims(
            signingKeys: [mislabelled], licenseKey: "K", now: Self.issuedAt)
        #expect(verified.key.kid == mislabelled.kid)
    }

    /// The served id still matches, so the lenient branch is genuinely an
    /// `either` and not a replacement.
    @Test("a claim naming the published kid is matched too")
    func servedIdMatchIsStillHonoured() throws {
        let signer = Keypair()
        let other = Keypair()
        let mislabelled = TamgaSigningKey(kid: "0000000000000000",
                                          publicKey: signer.publishedPublicKey)

        let forged = try LicenseFile.parse(
            Self.plainLicense(signedBy: other, claimingKid: mislabelled.kid))
        let error = checkoutError {
            _ = try forged.verifyWithClaims(
                signingKeys: [mislabelled], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(error?.caseName == "signatureVerificationFailed")

        // A claim naming neither is the unknown-key case, which is what stops
        // the two errors collapsing into one.
        let stranger = try LicenseFile.parse(
            Self.plainLicense(signedBy: other, claimingKid: "cccccccccccccccc"))
        let unknown = signingKeyError {
            _ = try stranger.verifyWithClaims(
                signingKeys: [mislabelled], licenseKey: "K", now: Self.issuedAt)
        }
        #expect(unknown == .unknownSigningKey(kid: "cccccccccccccccc",
                                              available: ["0000000000000000"]))
    }
}
