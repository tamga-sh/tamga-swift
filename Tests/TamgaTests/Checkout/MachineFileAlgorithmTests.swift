import Testing

@testable import Tamga

/// `MachineFileAlgorithm.parse` on its own.
///
/// The suite that matters most is the near-miss table: `alg` is not covered by
/// the signature, so on a file that otherwise verifies every byte of it is
/// attacker-chosen. The check it replaced was
/// `alg.contains("aes-256-gcm") ... else if alg.contains("base64")`, which
/// accepted every string in that table.
@Suite("MachineFileAlgorithm")
struct MachineFileAlgorithmTests {
    @Test(
        "parses every alg string the server can emit",
        arguments: [
            ("base64+ed25519+v2", MachineFileAlgorithm.Encoding.base64, "ed25519"),
            ("base64+ecdsa-p256+v2", .base64, "ecdsa-p256"),
            ("base64+rsa-sha256+v2", .base64, "rsa-sha256"),
            ("base64+rsa-pss-sha256+v2", .base64, "rsa-pss-sha256"),
            ("aes-256-gcm+ed25519+v2", .aes256Gcm, "ed25519"),
            ("aes-256-gcm+ecdsa-p256+v2", .aes256Gcm, "ecdsa-p256"),
            ("aes-256-gcm+rsa-sha256+v2", .aes256Gcm, "rsa-sha256"),
            ("aes-256-gcm+rsa-pss-sha256+v2", .aes256Gcm, "rsa-pss-sha256")
        ]
    )
    func parsesEveryServerAlgString(
        alg: String, encoding: MachineFileAlgorithm.Encoding, suffix: String
    ) throws {
        let parsed = try MachineFileAlgorithm.parse(alg)
        #expect(parsed.encoding == encoding)
        #expect(parsed.signingSuffix == suffix)
    }

    /// The delimiters are found from opposite ends because both the encoding
    /// prefix and two of the four suffixes contain hyphens. Splitting on `-`,
    /// or taking `+`-separated index 1 off a `split_once`, gets `ed25519` right
    /// and these wrong -- which is why the fleet-wide bug survived: the default
    /// scheme is the one case a broken parser handles.
    @Test("the hyphenated prefix and suffix do not bleed into each other")
    func hyphenatedSegmentsDoNotBleed() throws {
        let parsed = try MachineFileAlgorithm.parse("aes-256-gcm+rsa-pss-sha256+v2")
        #expect(parsed.encoding == .aes256Gcm)
        #expect(parsed.signingSuffix == "rsa-pss-sha256")
        // And specifically not the `rsa-sha256` that `rsa-pss-sha256` contains.
        #expect(parsed.signingSuffix != "rsa-sha256")
    }

    @Test(
        "rejects every near-miss a substring check would have accepted",
        arguments: [
            "base64+ed25519+v3",
            "base64+ed25519+v1",
            "base64+ed25519+v2junk",
            "base64+ed25519+V2",
            "base64+ed25519+",
            "base64+ed25519",
            "xbase64+ed25519+v2",
            "base64x+ed25519+v2",
            " base64+ed25519+v2",
            "aes-256-gcm-x+ed25519+v2",
            "base64++v2",
            "+ed25519+v2",
            "base64",
            "",
            "+",
            "++"
        ]
    )
    func rejectsNearMisses(alg: String) {
        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineFileAlgorithm.parse(alg)
        }
    }

    /// `+v2` is checked before the encoding prefix, so a v1 file is refused for
    /// being v1 rather than for whatever else it happens to say.
    @Test("a missing +v2 is reported as a missing +v2, not as a bad prefix")
    func versionIsCheckedFirst() {
        #expect(throws: TamgaCheckoutError.self) {
            _ = try MachineFileAlgorithm.parse("bogus-encoding+ed25519+v1")
        }
        guard case .unsupportedAlgorithm(let message)? = capture({
            _ = try MachineFileAlgorithm.parse("bogus-encoding+ed25519+v1")
        }) else {
            Issue.record("expected unsupportedAlgorithm")
            return
        }
        #expect(message.contains("+v2"))
    }

    @Test("the suffix mapping matches the server's scheme_to_alg_suffix")
    func suffixMappingMatchesTheServer() {
        #expect(MachineFileAlgorithm.signingSuffix(for: .ed25519Sign) == "ed25519")
        // An unset scheme is signed Ed25519 server-side, so it maps the same.
        #expect(MachineFileAlgorithm.signingSuffix(for: LicenseScheme.none) == "ed25519")
        #expect(MachineFileAlgorithm.signingSuffix(for: .ecdsaP256Sign) == "ecdsa-p256")
        #expect(MachineFileAlgorithm.signingSuffix(for: .rsa2048Pkcs1Sign) == "rsa-sha256")
        #expect(MachineFileAlgorithm.signingSuffix(for: .rsa2048Pkcs1PssSign) == "rsa-pss-sha256")
        // No verifiable machine-file form: the server refuses it at checkout,
        // and `nil` is what makes `MachineFile` refuse it before parsing.
        #expect(MachineFileAlgorithm.signingSuffix(for: .rsa2048JwtRs256) == nil)
    }

    private func capture(_ body: () throws -> Void) -> TamgaCheckoutError? {
        do {
            try body()
            return nil
        } catch let error as TamgaCheckoutError {
            return error
        } catch {
            return nil
        }
    }
}
