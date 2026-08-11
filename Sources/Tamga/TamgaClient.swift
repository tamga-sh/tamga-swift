/// `TamgaClient.swift`
///
/// STUB -- scaffolding only. No business logic is implemented yet; this file exists
/// so the package layout is syntactically valid and the eventual public API surface
/// has a home. See `docs/plans/tamga-swift.plan.md` Section C onward for the full
/// task breakdown this file will eventually satisfy.
///
/// Intended contents once implemented (do not build networking/crypto here yet --
/// see CLAUDE.md's crypto-boundary rule):
///
/// - `TamgaClientConfiguration`: `accountId` (required), `baseURL`, `apiVersion`
///   (defaults pinned per SDK major version, NOT the server's `"1.8"` default).
/// - `TamgaClient`: the top-level entry point holding a `Transport` and exposing
///   one async method per server endpoint documented in `docs/sdk.md`:
///     - License validation: `validateByKey`, `validateById`, `quickValidate`
///     - License check-in: `checkIn`
///     - License checkout: `checkOutLicense` (GET + POST variants)
///     - Machine management: `createMachine`, `activateMachine`, `pingHeartbeat`,
///       `resetHeartbeat`
///     - Machine checkout: `checkOutMachine` (GET + POST variants)
///     - Machine offline proof: `generateOfflineProof`
///     - Components & processes: `createComponent`, `listComponents`,
///       `createProcess`, `pingProcess`
///     - Entitlements: `listEntitlements`, `getEntitlement`
///
/// Every method must always send `Authorization: License <key>` (the primary
/// transport for this embedded SDK) even though no auth is currently enforced
/// server-side on the validation endpoints -- see docs/sdk.md's
/// "Known Server-Side Gaps" item 3.
public enum TamgaClient {
    // Intentionally empty. Implementation deferred to a future session per
    // docs/plans/tamga-swift.plan.md Sections C-L.
}
