import Crypto
import Foundation
import Testing

@testable import Tamga

/// `TamgaSigningKey`, and above all the derivation of a `kid` from a public
/// key -- the one rule this whole feature rests on.
@Suite("TamgaSigningKey")
struct SigningKeyTests {
    // MARK: - The key-id rule, against bytes this repo did not produce

    /// Every `kid` in the server-generated fixture manifest reproduces from
    /// that fixture's own published public key under `keyId(forPublicKey:)`.
    ///
    /// Twelve fixtures, four signing schemes, all produced by the tamga-api
    /// encoder rather than by this repo -- so a client-side misreading of the
    /// rule cannot agree with itself here the way a self-generated fixture
    /// would let it.
    ///
    /// **What this proves and what it does not.** It proves the *hash rule*:
    /// first eight bytes of SHA-256 over the public key string, hex. It does
    /// **not** prove which key the live server hashes, because the fixture
    /// generator and the live checkout handlers differ on exactly that point --
    /// each fixture's `kid` is derived from its own scheme's key, while
    /// `check_out_machine.rs:125-127` derives it from
    /// `account.ed25519_public_key` whatever the scheme. That divergence is why
    /// `verifyWithClaims(signingKeys:scheme:...)` refuses non-Ed25519 schemes
    /// instead of trusting the claim.
    @Test("every server fixture's kid reproduces from its own public key", arguments: MachineFileFixture.all)
    func keyIdMatchesEveryServerFixture(fixture: MachineFileFixture) {
        #expect(TamgaSigningKey.keyId(forPublicKey: fixture.publicKeyB64) == fixture.kid)
    }

    /// The single most likely way to get this wrong: hashing the decoded key
    /// bytes instead of the base64 string.
    ///
    /// `key_id(ed25519_public_key: &str)` takes a string and calls
    /// `.as_bytes()` on it, so the base64 *text* is the preimage. Both forms
    /// are 32-ish bytes of plausible-looking input and both produce a
    /// plausible-looking hex id, so nothing about the output says which was
    /// used -- only a test comparing them does.
    @Test("the kid hashes the base64 string, not the decoded key bytes", arguments: MachineFileFixture.all)
    func keyIdHashesTheStringNotTheDecodedBytes(fixture: MachineFileFixture) throws {
        let decoded = try #require(Data(base64Encoded: fixture.publicKeyB64))
        let fromDecodedBytes = SHA256.hash(data: decoded)
            .prefix(8)
            .map { String(format: "%02x", $0) }
            .joined()

        #expect(TamgaSigningKey.keyId(forPublicKey: fixture.publicKeyB64) == fixture.kid)
        #expect(fromDecodedBytes != fixture.kid)
    }

    /// Eight bytes, so sixteen hex characters -- not eight characters, which is
    /// the other easy misreading of "first eight bytes ... hex-encoded".
    @Test("a kid is sixteen lowercase hex characters")
    func keyIdIsEightBytesOfHex() {
        let kid = TamgaSigningKey.keyId(forPublicKey: "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g=")
        #expect(kid.count == 16)
        #expect(kid.allSatisfy { $0.isHexDigit && !$0.isUppercase })
    }

    /// The server hashes whatever string is in the column, including an empty
    /// one: `key_id(account.ed25519_public_key.as_deref().unwrap_or_default())`
    /// (`check_out_license.rs:92-94`). An account predating the public-key
    /// backfill therefore stamps every file it signs with the SHA-256 of the
    /// empty string, which is one constant `kid` shared across every such
    /// account (`key_material.rs:78-82` records this as a real past state).
    /// Pinned here so the value is recognisable if it ever shows up in a
    /// support report.
    @Test("the empty-key legacy kid is the SHA-256 of the empty string")
    func keyIdOfTheEmptyStringIsTheLegacyConstant() {
        #expect(TamgaSigningKey.keyId(forPublicKey: "") == "e3b0c44298fc1c14")
    }

    @Test("different keys get different ids")
    func keyIdDiffersPerKey() {
        let first = TamgaSigningKey.keyId(forPublicKey: "AAAA")
        let second = TamgaSigningKey.keyId(forPublicKey: "AAAB")
        #expect(first != second)
    }

    // MARK: - The model

    @Test("ed25519(publicKey:) derives the kid rather than being told it")
    func ed25519FactoryDerivesTheKid() {
        let published = "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g="
        let key = TamgaSigningKey.ed25519(publicKey: published)

        #expect(key.kid == TamgaSigningKey.keyId(forPublicKey: published))
        #expect(key.kid == "dc45aa88aa947b02")
        #expect(key.algorithm == TamgaSigningKey.ed25519Algorithm)
        #expect(key.status == TamgaSigningKey.activeStatus)
        #expect(key.isRetired == false)
        #expect(key.keyIdIsSelfConsistent)
    }

    @Test("a key whose published id disagrees with its own bytes says so")
    func selfConsistencyIsCheckable() {
        let honest = TamgaSigningKey.ed25519(publicKey: "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g=")
        let mislabelled = TamgaSigningKey(kid: "0000000000000000", publicKey: honest.publicKey)

        #expect(honest.keyIdIsSelfConsistent)
        #expect(mislabelled.keyIdIsSelfConsistent == false)
        #expect(mislabelled.computedKeyId == honest.kid)
    }

    @Test("publicKeyBytes decodes the published base64, and is nil for anything else")
    func publicKeyBytesDecodes() throws {
        let key = TamgaSigningKey.ed25519(publicKey: "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g=")
        let bytes = try #require(key.publicKeyBytes)
        #expect(bytes.count == 32)

        #expect(TamgaSigningKey.ed25519(publicKey: "not base64 !!").publicKeyBytes == nil)
    }

    @Test("a retired key reports itself retired")
    func retiredKeyIsFlagged() {
        let retired = TamgaSigningKey(
            kid: "abc", publicKey: "AAAA", status: TamgaSigningKey.retiredStatus,
            created: Date(timeIntervalSince1970: 1), retired: Date(timeIntervalSince1970: 2)
        )
        #expect(retired.isRetired)
        #expect(retired.retired != nil)
    }

    // MARK: - Error rendering

    @Test("each signing-key error renders its own distinguishable message")
    func errorsRenderDistinctly() {
        let unknown = TamgaSigningKeyError.unknownSigningKey(kid: "deadbeefdeadbeef", available: ["aaaa"])
        let noneUsable = TamgaSigningKeyError.noUsableSigningKey(available: [])
        let notApplicable = TamgaSigningKeyError.keyIdNotApplicable(scheme: "RSA_2048_PKCS1_SIGN")

        #expect(unknown.errorDescription?.contains("deadbeefdeadbeef") == true)
        #expect(unknown.errorDescription?.contains("aaaa") == true)
        #expect(noneUsable.errorDescription?.contains("empty") == true)
        #expect(notApplicable.errorDescription?.contains("RSA_2048_PKCS1_SIGN") == true)

        // Non-empty availability lists are rendered too, not just counted.
        let noneUsableWithEntries = TamgaSigningKeyError.noUsableSigningKey(available: ["rsa-1"])
        #expect(noneUsableWithEntries.errorDescription?.contains("rsa-1") == true)

        let unknownWithNoKeys = TamgaSigningKeyError.unknownSigningKey(kid: "kid-1", available: [])
        #expect(unknownWithNoKeys.errorDescription?.contains("kid-1") == true)
    }
}
