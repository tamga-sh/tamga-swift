import Foundation
import Testing

@testable import Tamga

/// `MachineFile` against real `.machine` files the tamga-api server produced
/// with its own `encode_machine_file`.
///
/// Everything here iterates `MachineFileFixture.all`, which is read from
/// `manifest.json` at load time. Fixtures added to the manifest are covered
/// with no edit to this file.
///
/// Why the fixtures are not generated here: the bug this suite exists to catch
/// survived two years of green CI in eight SDKs, because every one of them
/// verified its machine-file reader against a file it had encoded itself. Both
/// sides of each test shared one misreading of the wire format, so the tests
/// agreed with the code and neither agreed with the server. A test that can
/// only be satisfied by bytes this repo did not produce is the point.
@Suite("MachineFile — server-issued fixtures")
struct MachineFileServerFixtureTests {
    // MARK: - Format

    @Test(
        "the manifest describes the certificate the file actually carries",
        arguments: MachineFileFixture.all
    )
    func algMatchesTheManifest(fixture: MachineFileFixture) throws {
        let certificate = try fixture.certificate()
        #expect(certificate.alg == fixture.alg)

        let algorithm = try MachineFileAlgorithm.parse(certificate.alg)
        #expect(algorithm.encoding == (fixture.encrypted ? .aes256Gcm : .base64))
        #expect(certificate.alg.hasSuffix("+\(MachineFileAlgorithm.versionMarker)"))
    }

    /// M2, stated as bluntly as it can be: an encrypted machine file's `enc` is
    /// two SEPARATELY base64-encoded halves joined by a `.`, not one base64
    /// blob with a nonce on the front. The manifest states which it is, so this
    /// compares the SDK's reading against the generator's rather than against
    /// an assumption made in this repo.
    @Test(
        "enc framing matches the manifest, and an encrypted enc is not itself base64",
        arguments: MachineFileFixture.all
    )
    func encFramingMatchesTheManifest(fixture: MachineFileFixture) throws {
        let enc = try fixture.certificate().enc
        #expect(enc.contains(".") == fixture.encIsDotSeparated)

        if fixture.encIsDotSeparated {
            // The `.` is outside base64's alphabet, so the whole string cannot
            // decode. Treating it as one blob is not merely wrong about where
            // the nonce is -- there is nothing there to decode at all.
            #expect(Data(base64Encoded: enc) == nil)

            let halves = enc.split(separator: ".", omittingEmptySubsequences: false)
            #expect(halves.count == 2)
            let nonce = try #require(Data(base64Encoded: String(halves[0])))
            #expect(nonce.count == AesGcmCipher.nonceLength)
            let ciphertextAndTag = try #require(Data(base64Encoded: String(halves[1])))
            #expect(ciphertextAndTag.count > AesGcmCipher.tagLength)
        } else {
            #expect(Data(base64Encoded: enc) != nil)
        }
    }

    // MARK: - The happy path, and expiry

    @Test(
        "verifies at issue time and returns the signed payload, unless the manifest says it is expired",
        arguments: MachineFileFixture.all
    )
    func verifiesAtIssueTime(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)
        let claims = try fixture.claims()

        // Issue time, taken from the file's own signed `iat`, rather than the
        // wall clock: these fixtures carry a one-hour TTL, so a suite pinned to
        // `Date()` would pass on the day they were generated and fail forever
        // after.
        let issuedAt = claims.iat

        if fixture.expired {
            let error = checkoutError {
                _ = try file.verifyWithClaims(
                    scheme: scheme, publicKey: publicKey,
                    licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                    now: issuedAt
                )
            }
            // Distinctly `expired`, never `signatureVerificationFailed`: a
            // caller has to be able to tell "fetch a fresh file" from "this
            // file may be forged".
            #expect(error?.caseName == "expired")
            if case .expired(let exp)? = error {
                #expect(exp == claims.exp)
            }
            return
        }

        let result = try file.verifyWithClaims(
            scheme: scheme, publicKey: publicKey,
            licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
            now: issuedAt
        )
        #expect(result.machine.fingerprint == fixture.fingerprint)
        #expect(result.claims.kid == fixture.kid)
        #expect(!result.claims.jti.isEmpty)
    }

    /// The claims are not merely parsed, they gate the result. Same file, same
    /// signature, one hour and a minute later.
    @Test(
        "a file that is valid at issue time is rejected once its own exp has passed",
        arguments: MachineFileFixture.all.filter { !$0.expired }
    )
    func expiryIsEnforcedAgainstTheSuppliedClock(fixture: MachineFileFixture) throws {
        let file = try MachineFile.parse(fixture.pem())
        let scheme = try #require(fixture.licenseScheme)
        let publicKey = try #require(fixture.publicKey)
        let claims = try fixture.claims()

        // A fixture checked out with no `ttl` has no `exp` and genuinely never
        // expires -- absence is legitimate, so there is nothing to assert.
        guard let exp = claims.exp else { return }

        // Just inside the skew tolerance: still good.
        let stillValid = try file.verifyWithClaims(
            scheme: scheme, publicKey: publicKey,
            licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
            now: exp + LicenseFile.clockSkewToleranceSeconds
        )
        #expect(stillValid.claims.exp == exp)

        // One second past it: rejected.
        let error = checkoutError {
            _ = try file.verifyWithClaims(
                scheme: scheme, publicKey: publicKey,
                licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
                now: exp + LicenseFile.clockSkewToleranceSeconds + 1
            )
        }
        #expect(error?.caseName == "expired")
    }

    // MARK: - The fixture set itself

    @Test("the fixture set covers all four signing schemes the server can emit")
    func fixtureSetCoversEverySigningScheme() {
        let suffixes = Set(MachineFileFixture.all.compactMap { try? MachineFileAlgorithm.parse($0.alg).signingSuffix })
        #expect(suffixes == ["ed25519", "ecdsa-p256", "rsa-sha256", "rsa-pss-sha256"])
        #expect(MachineFileFixture.all.contains { $0.encrypted })
        #expect(MachineFileFixture.all.contains { $0.expired })
    }

    @Test("every manifest entry names a file that is actually bundled", arguments: MachineFileFixture.all)
    func everyManifestEntryHasItsFile(fixture: MachineFileFixture) throws {
        let pem = try fixture.pem()
        #expect(pem.contains("-----BEGIN MACHINE FILE-----"))
        #expect(fixture.licenseScheme != nil, "unmapped scheme '\(fixture.scheme)' in the manifest")
        #expect(fixture.publicKey != nil)
        #expect(fixture.encrypted == (fixture.licenseKey != nil))
    }
}
