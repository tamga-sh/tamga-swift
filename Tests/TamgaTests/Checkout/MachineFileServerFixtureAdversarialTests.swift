import Foundation
import Testing

@testable import Tamga

/// The adversarial half of the server-fixture suite: what a holder of a real,
/// validly-signed `.machine` file can do to it, and what must happen when they
/// do.
///
/// The signature covers `enc` and nothing else. `alg` and `sig` sit outside it,
/// so on a file that otherwise verifies perfectly, `alg` is entirely
/// attacker-chosen -- which is what makes strict parsing of it a security
/// property rather than tidiness. Split from
/// `MachineFileServerFixtureTests` only to keep each file under the 400-line
/// lint ceiling; the two share `MachineFileFixture`.
@Suite("MachineFile — server-issued fixtures, adversarial")
struct MachineFileServerFixtureAdversarialTests {
    // MARK: - Tampering

    @Test(
        "a tampered enc fails signature verification, before any decode or decrypt is attempted",
        arguments: MachineFileFixture.all
    )
    func tamperedEncFailsSignatureVerification(fixture: MachineFileFixture) throws {
        let certificate = try fixture.certificate()
        let tampered = MachineFileFixture.tampering(certificate.enc)
        #expect(tampered != certificate.enc)

        let file = try MachineFile.parse(try fixture.rewrapped(enc: tampered))
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)

        #expect(try !file.verify(scheme: scheme, publicKey: publicKey))

        let error = checkoutError {
            _ = try file.verifyAndDecrypt(
                scheme: scheme, publicKey: publicKey,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint
            )
        }
        // The tampering leaves `enc` structurally intact -- still valid base64,
        // still a two-part dot pair where it was one -- so a verifier that
        // decoded or decrypted first would get as far as an AES-GCM tag failure
        // or a JSON parse error and report one of those. Landing on
        // `signatureVerificationFailed` is what proves nothing downstream ran.
        #expect(error?.caseName == "signatureVerificationFailed")
    }

    @Test(
        "the wrong fingerprint fails decryption, distinctly from a signature failure",
        arguments: MachineFileFixture.all.filter(\.encrypted)
    )
    func wrongFingerprintFailsDecryption(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)

        let error = checkoutError {
            _ = try file.verifyAndDecrypt(
                scheme: scheme, publicKey: publicKey,
                licenseKey: fixture.licenseKey ?? "",
                fingerprint: "not-the-machine-this-was-issued-for"
            )
        }
        // The signature over `enc` is genuinely valid; only the HKDF-derived
        // key differs, so this must not be reported as a forgery.
        #expect(error?.caseName == "decryptionFailed")
    }

    @Test(
        "the wrong license key fails decryption",
        arguments: MachineFileFixture.all.filter(\.encrypted)
    )
    func wrongLicenseKeyFailsDecryption(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)

        let error = checkoutError {
            _ = try file.verifyAndDecrypt(
                scheme: scheme, publicKey: publicKey,
                licenseKey: "TAMGA-WRONG-LICENSE-KEY", fingerprint: fixture.fingerprint
            )
        }
        #expect(error?.caseName == "decryptionFailed")
    }

    // MARK: - alg

    /// M1. `alg` is outside the signature, so stripping `+v2` costs an attacker
    /// one edit and leaves the file cryptographically valid. A verifier that
    /// only substring-matched the encoding prefix accepted the result, which
    /// re-admits a format with no signed `exp` and an AES key derived by
    /// zero-padding the license key.
    @Test(
        "a downgraded alg with no +v2 is rejected, even though its signature still verifies",
        arguments: MachineFileFixture.all
    )
    func downgradedAlgIsRejected(fixture: MachineFileFixture) throws {
        let downgraded = fixture.alg.replacingOccurrences(of: "+\(MachineFileAlgorithm.versionMarker)", with: "")
        #expect(downgraded != fixture.alg)

        let file = try MachineFile.parse(try fixture.rewrapped(alg: downgraded))
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)

        let error = checkoutError { _ = try file.verify(scheme: scheme, publicKey: publicKey) }
        #expect(error?.caseName == "unsupportedAlgorithm")
    }

    @Test(
        "alg variants a substring check would have accepted are rejected",
        arguments: MachineFileFixture.all.filter { !$0.encrypted }
    )
    func nearMissAlgStringsAreRejected(fixture: MachineFileFixture) throws {
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)
        let suffix = try MachineFileAlgorithm.parse(fixture.alg).signingSuffix

        // Every one of these contains "base64" and the right signing suffix, so
        // the `alg.contains(...)` pair this replaces accepted all of them.
        let nearMisses = [
            "base64+\(suffix)+v3",
            "base64+\(suffix)+v2junk",
            "xbase64+\(suffix)+v2",
            "base64+\(suffix)",
            "base64+\(suffix)+v1",
            "not-an-encoding+\(suffix)+v2",
            "base64++v2"
        ]

        for alg in nearMisses {
            let file = try MachineFile.parse(try fixture.rewrapped(alg: alg))
            let error = checkoutError { _ = try file.verify(scheme: scheme, publicKey: publicKey) }
            #expect(error?.caseName == "unsupportedAlgorithm", "alg '\(alg)' should have been rejected")
        }
    }

    /// Swapping the encoding prefix is the other half of an attacker-controlled
    /// `alg`: it re-points the payload branch at a decoder the bytes were never
    /// framed for. It must fail cleanly rather than reach a decrypt.
    @Test(
        "an encoding prefix that contradicts the payload fails cleanly",
        arguments: MachineFileFixture.all.filter { !$0.encrypted && !$0.expired }
    )
    func swappedEncodingPrefixFailsCleanly(fixture: MachineFileFixture) throws {
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)
        let suffix = try MachineFileAlgorithm.parse(fixture.alg).signingSuffix

        let file = try MachineFile.parse(try fixture.rewrapped(alg: "aes-256-gcm+\(suffix)+v2"))
        let error = checkoutError {
            _ = try file.verifyAndDecrypt(
                scheme: scheme, publicKey: publicKey,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint
            )
        }
        // No dot in a plain file's `enc`, so the dot-separated reader refuses it
        // as malformed rather than slicing a nonce out of the payload.
        #expect(error?.caseName == "offlineFileFormat")
    }

    /// The mirror of `swappedEncodingPrefixFailsCleanly`, and a standing guard
    /// on `Data(base64Encoded:)` being used STRICTLY here.
    ///
    /// A dot-separated `enc` relabelled `base64+...` must fail. It does today
    /// because Foundation's decoder rejects the `.` by default -- but pass
    /// `.ignoreUnknownCharacters` and it becomes lenient, silently drops the
    /// `.`, and decodes `nonce_b64 + cipher_b64` as one stream. Both halves are
    /// a multiple of 4 characters long, so that concatenation reconstructs
    /// `nonce || ciphertext || tag` byte-for-byte and the old 12-byte slice
    /// lands correctly by accident. That is exactly what happens in the SDKs
    /// built on CPython's and Node's lenient decoders, where this bug is
    /// wrong-by-construction but not observable. If anyone ever "helpfully"
    /// makes this decoder forgiving, this test is what notices.
    @Test(
        "an encrypted enc relabelled as plain base64 is refused, not leniently decoded",
        arguments: MachineFileFixture.all.filter(\.encrypted)
    )
    func dotSeparatedEncIsNotAcceptedAsPlainBase64(fixture: MachineFileFixture) throws {
        let suffix = try MachineFileAlgorithm.parse(fixture.alg).signingSuffix
        let file = try MachineFile.parse(try fixture.rewrapped(alg: "base64+\(suffix)+v2"))
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)

        let error = checkoutError {
            _ = try file.verifyAndDecrypt(
                scheme: scheme, publicKey: publicKey,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint
            )
        }
        #expect(error?.caseName == "offlineFileFormat")
    }

    @Test(
        "a file may not be verified under a scheme its own alg contradicts",
        arguments: MachineFileFixture.all
    )
    func schemeMismatchIsRejected(fixture: MachineFileFixture) throws {
        let actual = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)
        let file = try MachineFile.parse(fixture.pem())

        let others: [LicenseScheme] = [.ed25519Sign, .ecdsaP256Sign, .rsa2048Pkcs1Sign, .rsa2048Pkcs1PssSign]
        for scheme in others where MachineFileAlgorithm.signingSuffix(for: scheme)
            != MachineFileAlgorithm.signingSuffix(for: actual) {
            let error = checkoutError { _ = try file.verify(scheme: scheme, publicKey: publicKey) }
            // Rejected on the cross-check, not merely returned `false` by a
            // verifier handed a key of the wrong type.
            #expect(error?.caseName == "unsupportedAlgorithm", "\(fixture.name) under \(scheme.rawValue)")
        }
    }

    // MARK: - Scheme confusion

    @Test(
        "RSA_2048_JWT_RS256 is refused before anything else happens",
        arguments: MachineFileFixture.all
    )
    func jwtRs256IsRefusedUpFront(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let publicKey = try #require(fixture.publicKey)

        let error = checkoutError { _ = try file.verify(scheme: .rsa2048JwtRs256, publicKey: publicKey) }
        #expect(error?.caseName == "schemeNotSupported")
    }

    /// The reason the scheme has to come from the caller and cannot be read out
    /// of the file: `RSA_2048_PKCS1_SIGN` and `RSA_2048_JWT_RS256` both
    /// serialize to `rsa-sha256`, so these are the SAME bytes with the SAME
    /// `alg`, and the only thing separating "verifies" from "refused" is the
    /// scheme the caller supplied from its own license record.
    @Test("an identical rsa-sha256 file verifies under PKCS1 and is refused under JWT_RS256")
    func rsaSha256SuffixCannotNameItsOwnScheme() throws {
        let candidates = MachineFileFixture.declaring(signingSuffix: "rsa-sha256").filter { !$0.expired }
        #expect(!candidates.isEmpty, "the manifest should carry at least one rsa-sha256 fixture")

        for fixture in candidates {
            let file = try MachineFile.parse(fixture.pem())
            let publicKey = try #require(fixture.publicKey)

            #expect(try file.verify(scheme: .rsa2048Pkcs1Sign, publicKey: publicKey))

            let error = checkoutError { _ = try file.verify(scheme: .rsa2048JwtRs256, publicKey: publicKey) }
            #expect(error?.caseName == "schemeNotSupported")
        }
    }
}
