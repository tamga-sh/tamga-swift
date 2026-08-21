import Foundation
import Testing

@testable import Tamga

/// `GET /v1/accounts/{accountId}/signing-keys`.
@Suite("Signing keys endpoint")
struct SigningKeysEndpointTests {
    /// A response shaped exactly like `signing_keys_response` builds it:
    /// `id` is the `kid`, `publicKey` is camelCase in an otherwise snake_case
    /// attribute bag, and `retired` is **absent** rather than null on the
    /// active key (`#[serde(skip_serializing_if = "Option::is_none")]`).
    static let body = """
    {"data":[
      {"type":"signing-keys","id":"dc45aa88aa947b02","attributes":{
        "algorithm":"ed25519",
        "publicKey":"AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g=",
        "status":"active",
        "created":"2026-08-01T10:00:00Z"}},
      {"type":"signing-keys","id":"5f301887c15a1d3d","attributes":{
        "algorithm":"ed25519",
        "publicKey":"AAAA",
        "status":"retired",
        "created":"2025-01-01T10:00:00Z",
        "retired":"2026-08-01T10:00:00.500Z"}}
    ]}
    """

    @Test("the request goes to the account's signing-keys collection")
    func requestPath() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.body)
        _ = try await TamgaClient.mocked(performer).listSigningKeys()

        let url = await performer.request(at: 0)?.url
        #expect(url?.path == "/v1/accounts/acct-123/signing-keys")
        #expect(await performer.request(at: 0)?.httpMethod == "GET")
    }

    /// `publicKey` has no underscore, so `convertFromSnakeCase` leaves it
    /// alone and the one camelCase field in a snake_case bag needs no custom
    /// `CodingKeys`. Asserted rather than assumed -- it is the field the whole
    /// feature depends on.
    @Test("the camelCase publicKey survives the snake-case decoder")
    func decodesTheKeySet() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: Self.body)
        let keys = try await TamgaClient.mocked(performer).listSigningKeys()

        #expect(keys.count == 2)

        let active = keys[0]
        #expect(active.kid == "dc45aa88aa947b02")
        #expect(active.algorithm == "ed25519")
        #expect(active.publicKey == "AQAg/HkMCKUVnpDfZAVDWheJo2UmA6fiBHTUDgCFC0g=")
        #expect(active.status == "active")
        #expect(active.isRetired == false)
        #expect(active.retired == nil)
        #expect(active.created != nil)
        // The published id really is the derived one, on a body shaped like
        // the server's.
        #expect(active.keyIdIsSelfConsistent)

        let retired = keys[1]
        #expect(retired.isRetired)
        #expect(retired.retired != nil)
    }

    /// An account that has never rotated has no rows at all, because
    /// `account_signing_keys` is written only by `rotate_ed25519`. That is a
    /// normal state and must decode, not throw.
    @Test("an empty key set decodes as an empty array")
    func emptyKeySetDecodes() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: #"{"data":[]}"#)
        let keys = try await TamgaClient.mocked(performer).listSigningKeys()
        #expect(keys.isEmpty)
    }

    /// Every attribute is optional in the wire struct, so one unexpected
    /// omission degrades that field rather than failing the whole list.
    @Test("a row missing attributes degrades instead of failing the list")
    func missingAttributesDegrade() async throws {
        let performer = MockPerformer()
        await performer.enqueue(body: #"{"data":[{"type":"signing-keys","id":"abc"}]}"#)
        let keys = try await TamgaClient.mocked(performer).listSigningKeys()

        #expect(keys.count == 1)
        #expect(keys[0].kid == "abc")
        #expect(keys[0].algorithm == TamgaSigningKey.ed25519Algorithm)
        #expect(keys[0].publicKey.isEmpty)
        #expect(keys[0].publicKeyBytes?.isEmpty ?? true)
    }

    /// The route needs `account.read`, which a licence token does not hold, so
    /// this is what an embedded client actually sees. Surfaced as an ordinary
    /// API error to match on, not swallowed.
    @Test("a licence-token 403 surfaces as an API error")
    func forbiddenSurfaces() async throws {
        let performer = MockPerformer()
        await performer.enqueue(
            status: 403,
            body: #"{"errors":[{"code":"FORBIDDEN","detail":"insufficient permissions"}]}"#)

        await #expect(throws: TamgaError.self) {
            _ = try await TamgaClient.mocked(performer).listSigningKeys()
        }
    }

    /// End to end: fetch a key set and verify a file against it without the
    /// caller ever computing an id by hand.
    @Test("a fetched key set feeds straight into offline verification")
    func fetchedKeysVerifyAFile() async throws {
        let fixture = try #require(MachineFileFixture.all.first { $0.licenseScheme == .ed25519Sign })
        let body = """
        {"data":[{"type":"signing-keys","id":"\(fixture.kid)","attributes":{
          "algorithm":"ed25519","publicKey":"\(fixture.publicKeyB64)",
          "status":"active","created":"2026-08-01T10:00:00Z"}}]}
        """

        let performer = MockPerformer()
        await performer.enqueue(body: body)
        let keys = try await TamgaClient.mocked(performer).listSigningKeys()

        let file = try MachineFile.parse(fixture.pem())
        let claims = try fixture.claims()
        let verified = try file.verifyWithClaims(
            signingKeys: keys, scheme: .ed25519Sign,
            licenseKey: fixture.licenseKey ?? "", fingerprint: fixture.fingerprint,
            now: claims.iat)

        #expect(verified.key.kid == fixture.kid)
    }
}
