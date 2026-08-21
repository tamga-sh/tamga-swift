import Crypto
import Foundation
import Testing

@testable import Tamga

/// Key-set verification of `.machine` files, driven by the server-issued
/// fixtures rather than by anything this repo encoded.
///
/// The Ed25519 fixtures exercise the whole path end to end: the key set is
/// built from the public key the manifest publishes, the id is derived
/// locally, and it has to match the `kid` the server actually wrote into the
/// signed payload. The other three schemes exercise the refusal.
@Suite("MachineFile — signing-key selection")
struct MachineFileSigningKeyTests {
    static var ed25519Fixtures: [MachineFileFixture] {
        MachineFileFixture.all.filter { $0.licenseScheme == .ed25519Sign }
    }

    static var otherSchemeFixtures: [MachineFileFixture] {
        MachineFileFixture.all.filter {
            $0.licenseScheme != nil && $0.licenseScheme != .ed25519Sign
        }
    }

    /// A parameterised suite over an empty argument list passes without
    /// asserting anything. Both partitions are pinned so a manifest change
    /// that empties one fails here instead of quietly hollowing out the suite.
    @Test("both fixture partitions are non-empty")
    func fixturePartitionsAreNonEmpty() {
        #expect(Self.ed25519Fixtures.count == 3)
        #expect(Self.otherSchemeFixtures.count == 9)
        #expect(Self.ed25519Fixtures.count + Self.otherSchemeFixtures.count == MachineFileFixture.all.count)
    }

    /// The full loop against server bytes: publish → derive id → match claim →
    /// verify. Nothing in it is supplied by this repo except the derivation
    /// rule, which is the thing under test.
    @Test("an Ed25519 machine file verifies against a key set built from the published key",
          arguments: ed25519Fixtures)
    func ed25519FixtureVerifiesAgainstAKeySet(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let key = TamgaSigningKey.ed25519(publicKey: fixture.publicKeyB64)
        let issuedAt = try fixture.claims().iat

        if fixture.expired {
            let error = checkoutError {
                _ = try file.verifyWithClaims(
                    signingKeys: [key], scheme: .ed25519Sign,
                    licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                    now: issuedAt)
            }
            #expect(error?.caseName == "expired")
            return
        }

        let verified = try file.verifyWithClaims(
            signingKeys: [key], scheme: .ed25519Sign,
            licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
            now: issuedAt)

        #expect(verified.key.kid == fixture.kid)
        #expect(verified.claims.kid == fixture.kid)
        #expect(verified.machine.fingerprint == fixture.fingerprint)
    }

    /// An unset scheme means Ed25519 server-side (`check_out_machine.rs:68-73`),
    /// so it must mean Ed25519 here too rather than being refused.
    @Test("a .none scheme is treated as Ed25519, not refused", arguments: ed25519Fixtures)
    func noneSchemeIsAcceptedAsEd25519(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let key = TamgaSigningKey.ed25519(publicKey: fixture.publicKeyB64)
        let issuedAt = try fixture.claims().iat

        // Either it verifies or it is expired -- what it must not be is
        // `keyIdNotApplicable`.
        do {
            let verified = try file.verifyWithClaims(
                signingKeys: [key], scheme: LicenseScheme.none,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                now: issuedAt)
            #expect(verified.key.kid == fixture.kid)
        } catch let error as TamgaCheckoutError {
            #expect(error.caseName == "expired")
        }
    }

    /// The finding that shaped this API. For RSA and ECDSA the `kid` claim
    /// names the account's Ed25519 key -- not the key that signed the file --
    /// so matching on it would select a key that cannot verify anything.
    /// Refused explicitly rather than attempted.
    @Test("a non-Ed25519 machine file is refused rather than matched by kid",
          arguments: otherSchemeFixtures)
    func otherSchemesAreRefused(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let scheme = try #require(fixture.licenseScheme)
        let key = TamgaSigningKey.ed25519(publicKey: fixture.publicKeyB64)

        let error = signingKeyError {
            _ = try file.verifyWithClaims(
                signingKeys: [key], scheme: scheme,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                now: 0)
        }
        #expect(error == .keyIdNotApplicable(scheme: scheme.rawValue))
    }

    /// Refused before anything else is looked at, so the caller gets the real
    /// reason rather than a downstream symptom.
    @Test("the refusal comes before key-set and alg checks")
    func refusalPrecedesEverythingElse() throws {
        let fixture = try #require(Self.otherSchemeFixtures.first)
        let file = try MachineFile.parse(fixture.pem())
        let scheme = try #require(fixture.licenseScheme)

        let error = signingKeyError {
            _ = try file.verifyWithClaims(
                signingKeys: [], scheme: scheme,
                licenseKey: "", fingerprint: fixture.fingerprint, now: 0)
        }
        #expect(error == .keyIdNotApplicable(scheme: scheme.rawValue))
    }

    @Test("a machine file signed by a key outside the set names that key",
          arguments: ed25519Fixtures)
    func unknownKeyIsReported(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let stranger = TamgaSigningKey.ed25519(
            publicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString())

        let error = signingKeyError {
            _ = try file.verifyWithClaims(
                signingKeys: [stranger], scheme: .ed25519Sign,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                now: 0)
        }
        #expect(error == .unknownSigningKey(kid: fixture.kid, available: [stranger.kid]))
    }

    /// The discrimination, on server bytes: the right key is present and the
    /// payload has been altered, so this is tampering and not rotation.
    @Test("a tampered machine file whose key IS held reports a failed signature",
          arguments: ed25519Fixtures)
    func tamperedFixtureIsNotMistakenForRotation(fixture: MachineFileFixture) throws {
        let tampered = try fixture.rewrapped(
            enc: MachineFileFixture.tampering(fixture.certificate().enc))
        let file = try MachineFile.parse(tampered)
        let key = TamgaSigningKey.ed25519(publicKey: fixture.publicKeyB64)

        let error = checkoutError {
            _ = try file.verifyWithClaims(
                signingKeys: [key], scheme: .ed25519Sign,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                now: 0)
        }
        #expect(error?.caseName == "signatureVerificationFailed")
    }

    @Test("an empty key set is its own error for machine files too")
    func emptyKeySetIsItsOwnError() throws {
        let fixture = try #require(Self.ed25519Fixtures.first)
        let file = try MachineFile.parse(fixture.pem())

        let error = signingKeyError {
            _ = try file.verifyWithClaims(
                signingKeys: [], scheme: .ed25519Sign,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                now: 0)
        }
        #expect(error == .noUsableSigningKey(available: []))
    }

    /// The convenience form reads the system clock, and these fixtures carry a
    /// one-hour TTL that expired the day they were generated -- so it throwing
    /// `.expired` is the correct outcome and pins which clock it uses.
    @Test("verifyAndDecrypt(signingKeys:) uses the wall clock", arguments: ed25519Fixtures)
    func convenienceFormUsesTheWallClock(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let key = TamgaSigningKey.ed25519(publicKey: fixture.publicKeyB64)

        let error = checkoutError {
            _ = try file.verifyAndDecrypt(
                signingKeys: [key], scheme: .ed25519Sign,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint)
        }
        #expect(error?.caseName == "expired")
    }
}
