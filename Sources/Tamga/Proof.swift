import Foundation

/// Machine offline proof (air-gapped verification) -- docs/sdk.md §7.
///
/// **Scope note**: `generateOfflineProof` (the `POST
/// /machines/{id}/actions/generate-offline-proof` HTTP call itself) is part
/// of `TamgaClient`'s HTTP-facing surface and stays deferred to a future
/// session per `docs/plans/tamga-swift.plan.md` Section I, same as the rest
/// of that surface (see `Errors.swift`/`License.swift`/`Machine.swift`'s
/// scope notes). `MachineProof` below covers the proof-STRING
/// parsing/verification this architecture pivot needed: the canonical-JSON
/// signed-payload construction and RSA-2048 PKCS#1 v1.5/SHA-256 signature
/// check.
///
/// Builds the byte-exact canonical JSON payload an offline proof's RSA
/// signature covers, and parses/verifies a `meta.proof` string returned by
/// the generate-offline-proof endpoint.
///
/// Proof signing is ALWAYS RSA-2048 PKCS#1 v1.5 / SHA-256, regardless of the
/// license's `LicenseScheme` -- this type never dispatches by scheme, unlike
/// `Checkout.MachineFile`.
///
/// `meta.proof` has the shape `"v1x0.<base64 signature>"` -- `parse` splits
/// the version prefix from the signature and rejects malformed/missing-prefix
/// strings.
///
/// CRITICAL -- canonical payload field order: the signed payload is
/// `{"account":{"id":...},"machine":{"id":...,"fingerprint":...},"dataset":...}`
/// in literal source-code order is WRONG -- confirmed against tamga-dotnet's
/// own equivalent (which corrected this after reading the actual server
/// source, `tamga-api/src/features/machines/generate_offline_proof.rs`): the
/// server builds this payload via `serde_json::json!(...)`, whose backing
/// `serde_json::Map` is `BTreeMap`-backed (the `preserve_order`/`indexmap`
/// Cargo feature is enabled on neither `tamga-api` nor `tamga-rust`), so the
/// actual wire bytes are recursively **alphabetically key-sorted at every
/// nesting level**, not literal source order:
/// `{"account":{"id":...},"dataset":{...sorted...},"machine":{"fingerprint":...,"id":...}}`
/// -- note `dataset` sorts before `machine`, and inside `machine`,
/// `fingerprint` sorts before `id`. This applies recursively to whatever keys
/// the caller's own `dataset` object contains too. `buildSignedPayload`
/// implements this via `CanonicalJson`, a canonical (alphabetical, recursive)
/// JSON writer, rather than a fixed-property-order type.
public struct MachineProof {
    /// The only version prefix this SDK recognizes.
    public static let versionPrefix = "v1x0."

    /// The base64-encoded RSA signature, with the version prefix already stripped.
    let rawSignatureBase64: String

    private init(rawSignatureBase64: String) {
        self.rawSignatureBase64 = rawSignatureBase64
    }

    /// Parses a `meta.proof` string, splitting the `"v1x0."` version prefix
    /// from the base64 signature.
    ///
    /// - Throws: `TamgaCheckoutError.unsupportedAlgorithm` if the string is
    ///   missing the expected version prefix. `TamgaCheckoutError.offlineFileFormat`
    ///   if the prefix is present but the remaining signature is empty.
    public static func parse(_ proof: String) throws -> MachineProof {
        guard proof.hasPrefix(versionPrefix) else {
            throw TamgaCheckoutError.unsupportedAlgorithm("Unrecognized offline proof format: expected the '\(versionPrefix)' prefix.")
        }

        let signature = String(proof.dropFirst(versionPrefix.count))
        guard !signature.isEmpty else {
            throw TamgaCheckoutError.offlineFileFormat("Offline proof signature was empty after the version prefix.")
        }

        return MachineProof(rawSignatureBase64: signature)
    }

    /// Builds the exact canonical JSON byte string the server signs --
    /// recursively alphabetically key-sorted, matching `serde_json::json!()`'s
    /// `BTreeMap`-backed output. See type-level remarks for why this is NOT
    /// literal source order.
    public static func buildSignedPayload(accountId: String, machineId: String, fingerprint: String, dataset: JSONValue) -> String {
        let payload = JSONValue.object([
            "account": .object(["id": .string(accountId)]),
            "machine": .object([
                "id": .string(machineId),
                "fingerprint": .string(fingerprint),
            ]),
            "dataset": dataset,
        ])
        return CanonicalJson.serialize(payload)
    }

    /// Verifies this proof's RSA-2048 PKCS#1 v1.5/SHA-256 signature against
    /// the reconstructed canonical payload. Fails closed (returns `false`)
    /// on any mismatch, including a `dataset` that was altered post-signing.
    public func verify(publicKeyDER: Data, accountId: String, machineId: String, fingerprint: String, dataset: JSONValue) -> Bool {
        guard let signature = Data(base64Encoded: rawSignatureBase64) else {
            return false
        }

        let payload = Self.buildSignedPayload(accountId: accountId, machineId: machineId, fingerprint: fingerprint, dataset: dataset)
        let message = Data(payload.utf8)
        return Rsa.verifyPkcs1(publicKeyDER: publicKeyDER, message: message, signature: signature)
    }
}
