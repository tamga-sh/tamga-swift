# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-swift` is the official Swift SDK for Tamga, with Objective-C interoperability — license
activation and offline verification for macOS and iOS apps. It reimplements Tamga's cryptographic
verification logic natively in Swift (CryptoKit + the Security framework) — the same architecture as
`tamga-python`/`tamga-go`/`tamga-js`/`tamga-dotnet` — so divergence from the Rust reference
implementation in the crypto sections is a real interop bug, not a style choice. Full task
breakdown and current build status: [`../docs/plans/tamga-swift.plan.md`](../docs/plans/tamga-swift.plan.md)
(lives one directory up, in the sibling `tamga-sdk` monorepo, not inside this repo).
Protocol/feature spec this SDK is built against — every field name, endpoint, and enum value comes
from here: [`tamga-api/docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md).

**Current state: crypto/checkout/proof are real; HTTP client surface is still stub.**
`Sources/Tamga/Crypto/` (Ed25519, AES-256-GCM, HKDF-SHA256, ECDSA-P256, RSA PKCS1/PSS, the naive
license-key derivation), `Checkout/` (`LicenseFile`, `MachineFile`), and `Proof.swift`
(`MachineProof` + `CanonicalJson`) are implemented and tested (90+ tests, 96%+ line coverage). The
HTTP-facing surface (`TamgaClient`'s endpoint methods, `Transport.swift`, the full JSON:API error
model, entitlement caching, heartbeat scheduling, the full `Policy` struct) is still stub — see each
of those files' own doc comments for what's deferred and to which plan section. Do not assume any
method on `TamgaClient` does anything yet.

Until 2026-08-12 this package instead bound to `tamga-c` (the Rust reference implementation) via a
C FFI boundary and a `TamgaCore` binary target, mirroring `tamga-java`'s JNI approach — deliberately
replaced with the native reimplementation above. See "Why native, not bound to tamga-c" below for
the full rationale; the old XCFramework/binary-target CI machinery this section and "Critical
Dependency Notes" used to describe is gone, not just out of date.

## Crypto Architecture

The four crypto operations Tamga's protocol needs, and what backs each one in
`Sources/Tamga/Crypto/`:

1. Ed25519 verify (license checkout signature check) — CryptoKit `Curve25519.Signing`.
2. AES-256-GCM open (license file decrypt) — CryptoKit `AES.GCM`.
3. HKDF-SHA256 derive (machine file decrypt key derivation) — CryptoKit `HKDF<SHA256>`.
4. Multi-scheme verify — Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256 (machine checkout) and RSA-PKCS1v15
   (offline proof) — CryptoKit `P256.Signing` for ECDSA, the **Security framework**'s `SecKey` API
   for RSA (CryptoKit deliberately does not expose RSA; confirmed against Apple's own docs before
   writing `Crypto/Rsa.swift` — do not go looking for an RSA type in CryptoKit).

**`Crypto/Ecdsa.swift` has an explicit curve-OID check most callers would not expect to need.**
Confirmed directly (empirically, not assumed): CryptoKit's
`P256.Signing.PublicKey(derRepresentation:)` does NOT validate the curve OID in the
`AlgorithmIdentifier` it parses, only the resulting coordinate byte length. A hand-crafted SPKI
declaring the secp256k1 curve OID but carrying a real P-256 point's raw coordinates (same 65-byte
length) is silently accepted by CryptoKit's own parser. `Ecdsa.swift`'s guard (backed by
`DER.swift`'s minimal OID extractor) is what actually closes this — it is the exact curve-confusion
bug class a cross-repo security audit of this SDK family found live in
`tamga-python`/`tamga-go`/`tamga-dotnet`'s generic `ECDsa`-based verifiers, which had no equivalent
check. Do not remove this guard to "simplify" the type; see `EcdsaTests.swift`'s regression test for
what it protects against.

**Everything else is hand-rolled, idiomatic Swift.** HTTP transport is built on `URLSession`
directly — no crypto library is used for networking, JSON:API decoding, or the public client API
surface.

## Why native, not bound to tamga-c

`tamga-java` (JNI) still binds to `tamga-c`'s Rust reference implementation for these same 4
operations; `tamga-swift` deliberately does not, as of 2026-08-12. Both are legitimate designs with
a real tradeoff, not a strict improvement in one direction — this section exists so a future
contributor doesn't "fix" one architecture into looking like the other without re-deriving why this
one was chosen:

- **The original tamga-c-binding design's own stated rationale** (still true, still the reason
  `tamga-java` keeps it): binding to one audited reference implementation avoids maintaining and
  security-auditing N independent reimplementations of the same signature/encryption logic. A
  cross-repo audit of this SDK family found that risk was NOT hypothetical: the same ECDSA
  curve-confusion bug (see above) was independently present in 3 of 5 from-scratch
  reimplementations at the time.
- **The reason it was replaced here anyway**: the binding architecture's cross-platform build/CI
  cost turned out to be substantial in practice for this specific repo — the XCFramework
  assembly/distribution pipeline and Xcode-version/iOS-Simulator-runtime CI matching (see
  `.github/workflows/ci.yml`'s git history for the full account) were a recurring source of CI
  failures unrelated to the SDK's own correctness. Native CryptoKit/Security-framework code has none
  of that: no binary target, no XCFramework, no FFI boundary, no version-pairing to get right.
- **The mitigation for the reintroduced reimplementation risk**: `Ecdsa.swift`'s explicit curve-OID
  check above, plus mandatory adversarial security review before any crypto-path change merges — the
  SDK family's standard defense against exactly this risk class, applied here deliberately rather
  than assumed away.

## Three-Target Architecture

```
tamga-swift/
├── Package.swift                — SPM manifest: 3 targets, no binary target
├── Sources/
│   ├── Tamga/                    — public Swift API
│   │   ├── TamgaClient.swift     — top-level client: config, all endpoint methods (stub)
│   │   ├── Transport.swift       — URLSession-based HTTP layer, auth headers, content-type dispatch (stub)
│   │   ├── Errors.swift          — TamgaCheckoutError (real); TamgaError HTTP error model (stub)
│   │   ├── Proof.swift           — MachineProof: offline proof parse/verify
│   │   ├── CanonicalJson.swift   — recursive alphabetical-key-sorted JSON writer, for Proof
│   │   ├── Crypto/                — Ed25519, AesGcm, Hkdf, Ecdsa, Rsa, NaiveKey, DER — see "Crypto Architecture" above
│   │   ├── Models/                — License, Machine, LicenseScheme (real); ValidationCode, full Policy (stub)
│   │   └── Checkout/               — LicenseFile, MachineFile, PemEnvelope (PEM parse/verify/decrypt)
│   └── TamgaObjC/                — thin Objective-C interop wrapper over Tamga
├── Tests/TamgaTests/             — Swift Testing (import Testing, NOT XCTest)
├── Scripts/check-coverage.sh     — hand-written 80% line-coverage gate for CI
└── .github/workflows/
    ├── ci.yml                    — swiftlint + swift test (macOS) + xcodebuild test (iOS)
    └── release.yml               — release-please only; no binary-asset publish step (see that file's header comment)
```

`tamga-web`-equivalent: there is no server here. `Tamga` is the library target apps link against;
`TamgaObjC` is a thin wrapper for Objective-C-only consumers, not a separate implementation.

## Dev Commands

```bash
swift build                # Build all targets
swift test                 # Run TamgaTests (Swift Testing, not XCTest)
swift test --enable-code-coverage    # As CI runs it, before the coverage gate
swiftlint lint --strict    # As CI runs it — warnings fail under --strict
swift format .             # If/when swift-format is adopted (not yet wired)
```

There is no `just`-style task runner in this repo (unlike `tamga-api`) — SPM's own subcommands
are the whole toolchain. `Scripts/check-coverage.sh` is not meant to be run standalone during
normal dev; it expects `llvm-cov export -summary-only` JSON piped in, exactly as CI invokes it.

**First-time setup**: none needed beyond a normal Swift toolchain. `swift build`/`swift test` work
immediately on a fresh checkout — no sibling repo, no binary target, no local-dev override to apply.

## GOTCHAS — from `docs/sdk.md`'s "Known Server-Side Gaps"

These are real, verified discrepancies between what the server *appears* to support and what it
actually does. Building this SDK's UX around the wrong side of any of these will either silently
no-op or advertise a guarantee the server doesn't enforce. Only the gaps relevant to this SDK's
scope (license validation, checkout, machine management, offline proof) are listed — see the
source doc for the full set, including analytics/EE items that don't touch this SDK at all.

- **Auto-update/release-checking is explicitly out of scope for v1.** `GET
  /releases/actions/upgrade` crashes at runtime server-side (queries a `release_artifacts` table
  and columns that don't exist in any migration) and even once fixed has no working
  download-URL endpoint. Do not build any "check for update" client feature against it.
- **No auth is enforced server-side on license or machine endpoints today.** Still always send
  `Authorization: License <key>` (forward-compatible) — just don't build client-side logic that
  assumes a bad/missing credential gets rejected right now.
- **Only 14 of 24 `ValidationCode` values are reachable.** Model all 24 with lenient/unknown-value
  decoding, but don't build UI/UX around the 10 that are declared and never emitted
  (`BANNED`, `ENTITLEMENTS_MISSING`, `TOO_MANY_USERS`, `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`,
  `FINGERPRINT_SCOPE_MISMATCH`, `COMPONENTS_SCOPE_MISMATCH`, `CHECKSUM_SCOPE_MISMATCH`,
  `VERSION_SCOPE_MISMATCH`, and `NOT_FOUND` which surfaces as an HTTP 404 instead of this code).
  Same applies to `ValidationScope`'s `entitlements`/`fingerprint`/`version`/`checksum` fields —
  build the request field, don't advertise it as a functioning constraint.
- **No client-side 429/backoff handling.** `429 TOO_MANY_REQUESTS` is declared in the server's
  error enum but has no constructor and is never returned by any code path today. Do not add
  retry/backoff logic that waits for a 429 that will never come — it will just make the SDK feel
  broken when a real rate limiter is eventually added server-side with different semantics.
- **`Tamga-Environment` request header does nothing server-side.** It's a planned EE feature with
  no request-parsing code path yet. Don't expose a client-facing "environment" request option that
  implies it's honored today.
- **Fresh policies default to non-existent enum variants.** `overage_strategy` defaults to the
  literal string `"DENY_ACCESS"` and `heartbeat_resurrection_strategy` to `"NO_RESURRECTION"` —
  neither is a real variant of `OverageStrategy`/`HeartbeatResurrectionStrategy`. The server
  silently treats both as the "no restriction" variant (`NO_OVERAGE`/`NO_REVIVE`). Decoders here
  must not crash on these strings, and must not invent fake enum cases that imply restrictive
  behavior the server doesn't actually have.
- **Heartbeat windows are hardcoded, not policy-driven.** Machine heartbeat window is a hardcoded
  600s regardless of `policy.heartbeat_duration`; process heartbeat window is a hardcoded 30s with
  no resurrection grace period at all. Any heartbeat-scheduler helper in this SDK should derive its
  ping interval from these hardcoded constants, not from a policy value that the server ignores.
- **License checkout's AES key derivation is NOT a KDF.** It's the raw UTF-8 bytes of the license
  key, zero-padded or truncated to exactly 32 bytes. Running it through SHA-256 or any real KDF
  produces a key that silently fails to decrypt — this has bitten every SDK that assumed "hash the
  secret" was a safe default. Machine checkout, by contrast, *does* use a real HKDF-SHA256 — don't
  let the two crypto paths bleed into each other.
- **The license-checkout Ed25519 signature covers the base64 *string bytes* of `enc`, not its
  decoded bytes.** This is the single most common implementation bug across every Tamga SDK. See
  the `// CRITICAL:` comment in `Sources/Tamga/Checkout/LicenseFile.swift` once it's implemented.

## Testing

- Swift Testing (`import Testing`), **not XCTest** — this is a deliberate convention for this
  package (current idiom for Swift 5.9+/6), not a stopgap. New tests must use `@Test`/`@Suite`
  and `#expect`, not `XCTestCase`/`XCTAssert`.
- CI gates on 80% line coverage via `swift test --enable-code-coverage` →
  `xcrun llvm-cov export -summary-only` → `Scripts/check-coverage.sh`. Run the same pipeline
  locally before pushing if you're unsure a change clears the bar — see that script's header
  comment for the exact invocation.
- Two CI jobs must both pass: `swift test` on macOS, `xcodebuild test` against a fresh iOS
  Simulator device on iOS. The device is created at run time from whichever runtime matches the
  pinned Xcode's own default Simulator SDK (see `ci.yml`'s "Create an iOS Simulator device" step) —
  not a hardcoded device name, which proved unreliable across GitHub's runner pool. The coverage
  gate lives only in the macOS job, not the iOS one — they're intentionally not double-gated on the
  same threshold.
- Every `Tamga` type that touches the network must sit behind a protocol for test doubles (mock
  `URLSession` via a `MockURLProtocol` harness) — see the `ecc:swift-protocol-di-testing` skill. Do
  not hit live network from unit tests. There is no FFI boundary to mock anymore — `Crypto/` calls
  CryptoKit/Security directly, and its own tests use real (test-generated) keys and signatures
  rather than mocking the crypto itself; see `Tests/TamgaTests/Support/` for the shared fixture
  helpers (`RsaTestKey`, `CheckoutFixture`).

## Critical Dependency Notes

- **SPM has no central package registry for this SDK** — unlike `tamga-python` (PyPI) or
  `tamga-js` (npm), there is no name-collision concern and no publish step. The git tag *is* the
  release; `release.yml` (release-please only) is the entire release surface.
- **RSA is Security framework, not CryptoKit** — see "Crypto Architecture" above. This is the one
  crypto primitive in this SDK that doesn't use CryptoKit; don't "simplify" `Crypto/Rsa.swift` by
  looking for a CryptoKit RSA type that doesn't exist.

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/) format (`feat: …`, `fix: …`,
etc.) — `release-please` (release-type: `simple`) parses these directly to drive
`CHANGELOG.md` and version bumps. A commit that doesn't follow the convention is invisible to the
release automation, not just a style nit.
