# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-swift` is the official Swift SDK for Tamga, with Objective-C interoperability — license
activation and offline verification for macOS, iOS and Linux. It reimplements Tamga's cryptographic
verification logic natively in Swift (apple/swift-crypto) — the same architecture as
`tamga-python`/`tamga-go`/`tamga-js`/`tamga-dotnet` — so divergence from the Rust reference
implementation in the crypto sections is a real interop bug, not a style choice. The
protocol/feature spec this SDK is built against — every field name, endpoint, and enum value comes
from it — is the Tamga API protocol specification, which is not published; public-facing docs must
point at <https://tamga.sh> instead.

**Current state: complete.** `Sources/Tamga/Crypto/` (Ed25519, AES-256-GCM, HKDF-SHA256,
ECDSA-P256, RSA PKCS1/PSS, DER), `Checkout/`, `Proof.swift`, and the HTTP surface
(`TamgaClient`'s 20 endpoints, `Transport`, `AuthTransport`, the JSON:API error model,
`EntitlementCache`, both heartbeat schedulers, and the full `Policy` struct) are all implemented
and tested — 193 tests, ~84% line coverage against an 80% gate.

The normative description of the network surface is `../docs/api-client-contract.md`, derived from
`tamga-go`. Behavioural changes to `TamgaClient`/`Transport` should update that document too, or
the fleet drifts apart again.

**Three CI jobs must pass: macOS, iOS, and Linux.** The package is no longer Apple-only.

Until 2026-08-12 this package instead bound to `tamga-c` (the Rust reference implementation) via a
C FFI boundary and a `TamgaCore` binary target, mirroring `tamga-java`'s JNI approach — deliberately
replaced with the native reimplementation above. See "Why native, not bound to tamga-c" below for
the full rationale; the old XCFramework/binary-target CI machinery this section and "Critical
Dependency Notes" used to describe is gone, not just out of date.

## Crypto Architecture

The four crypto operations Tamga's protocol needs, and what backs each one in
`Sources/Tamga/Crypto/`:

1. Ed25519 verify (license checkout signature check) — `Crypto`'s `Curve25519.Signing`.
2. AES-256-GCM open (license/machine file decrypt) — `Crypto`'s `AES.GCM`.
3. HKDF-SHA256 derive (both file types' decrypt key derivation, with different salt/info per
   type — see the GOTCHAS section) — `Crypto`'s `HKDF<SHA256>`.
4. Multi-scheme verify — Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256 (machine checkout) and RSA-PKCS1v15
   (offline proof) — `Crypto`'s `P256.Signing` for ECDSA, and `CryptoExtras`' `_RSA.Signing` for
   RSA (neither CryptoKit nor swift-crypto's `Crypto` module exposes RSA — do not go looking).

**Everything runs on apple/swift-crypto, not CryptoKit directly.** On Apple platforms the `Crypto`
module forwards to CryptoKit, so this is a portable spelling of the same primitives rather than a
different backend there. RSA is the exception: it was on the Security framework, which is
Apple-only and made the package impossible to compile on Linux.

**swift-crypto is pinned to 4.x, and the floor is not cosmetic.** The 3.x line has a memory-safety
bug on the RSA public-key parse ERROR path: `_RSA.Signing.PublicKey(derRepresentation:)` corrupts
the heap when the DER fails to parse. Reproduced against 3.15.1 with a standalone probe — 2000
sequential malformed parses abort with `nanov2_guard_corruption_detected`, while valid parses never
do. It surfaced here as a flaky `signal 6` in the test suite roughly 5 runs in 6, because
`RsaTests` deliberately feeds `Rsa.verifyPkcs1` a malformed key. That path is reachable from
production with attacker-supplied bytes. Do not relax the pin back to 3.x.

**`Crypto/Ecdsa.swift` parses the signature as ASN.1 DER, not raw `(r, s)`.** The server signs with
`ECDSA_P256_SHA256_ASN1`. Confirmed against a real checked-out fixture: 71 bytes beginning `0x30`,
where a P1363 signature would be exactly 64 raw bytes. This previously used `rawRepresentation` and
rejected every genuine server-issued ECDSA machine file.

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

**Everything else is hand-rolled, idiomatic Swift.** HTTP transport goes on `URLSession` behind
the `HTTPRequestPerforming` protocol — no crypto library is used for networking, JSON:API decoding,
or the public client API surface.

## Why native, not bound to tamga-c

Both `tamga-swift` and `tamga-java` originally planned to bind to `tamga-c`'s Rust reference
implementation for these 4 operations, and **both pivoted to native reimplementation on
2026-08-12** — this file previously claimed tamga-java still binds via JNI, which has not been true
since that date (see `tamga-java/CLAUDE.md`'s "Why native, not bound to tamga-c"). Binding remains a
legitimate design with a real tradeoff, so this section exists to record why it was dropped rather
than let a future contributor "fix" one architecture back into the other:

- **The original tamga-c-binding design's own stated rationale** (still true in the abstract):
  binding to one audited reference implementation avoids maintaining and
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
│   │   ├── TamgaClient.swift     — top-level client, split across TamgaClient+*.swift extensions
│   │   ├── Transport.swift       — HTTPRequestPerforming seam, URL/auth/headers, 429 retry
│   │   ├── AuthTransport.swift   — the seven auth forms
│   │   ├── EntitlementCache.swift, HeartbeatScheduler.swift — actors
│   │   ├── Errors.swift          — TamgaError (API) and TamgaCheckoutError (offline)
│   │   ├── Proof.swift           — MachineProof: offline proof parse/verify
│   │   ├── CanonicalJson.swift   — recursive alphabetical-key-sorted JSON writer, for Proof
│   │   ├── Crypto/                — Ed25519, AesGcm, Hkdf, Ecdsa, Rsa, DER — see "Crypto Architecture" above
│   │   ├── Models/                — License, Machine, Component, MachineProcess, Entitlement,
│   │   │                             Policy, Scope, ValidationCode/Meta, Page, requests/results
│   │   └── Checkout/               — LicenseFile, MachineFile, PemEnvelope (PEM parse/verify/decrypt)
│   └── TamgaObjC/                — thin Objective-C interop wrapper over Tamga
├── Tests/TamgaTests/             — Swift Testing (import Testing, NOT XCTest)
├── Scripts/check-coverage.sh     — hand-written 80% line-coverage gate for CI
└── .github/workflows/
    ├── ci.yml                    — swiftlint + swift test + coverage (macOS), xcodebuild test
    │                                 (iOS), swift build/test (Linux, swift:6.1-jammy)
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

There is no `just`-style task runner in this repo — SPM's own subcommands are the whole toolchain.
`Scripts/check-coverage.sh` is not meant to be run standalone during normal dev; it expects
`llvm-cov export -summary-only` JSON piped in, exactly as CI invokes it.

**First-time setup**: none needed beyond a normal Swift toolchain. `swift build`/`swift test` work
immediately on a fresh checkout — no sibling repo, no binary target, no local-dev override to apply.

## GOTCHAS — from the Tamga API protocol specification's "Known Server-Side Gaps"

These are real, verified discrepancies between what the server *appears* to support and what it
actually does. Building this SDK's UX around the wrong side of any of these will either silently
no-op or advertise a guarantee the server doesn't enforce. Only the gaps relevant to this SDK's
scope (license validation, checkout, machine management, offline proof) are listed — the
specification covers the full set, including analytics/EE items that don't touch this SDK at all.

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
- **429 handling is required once the transport lands.** `429 TOO_MANY_REQUESTS` is live
  server-side. The contract the other SDKs already ship, and the one this SDK's `Transport` must
  match: parse `Retry-After` and cap it, back off with jittered exponential delays, and scope
  auto-retry to `GET` plus five safe `POST` actions (`validate`, `validate-key`, `check-in`,
  `check-out`, `ping`). Creates are deliberately excluded — retrying one risks a duplicate
  resource.
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
- **Both file types derive their AES key with HKDF-SHA256, but never with the same parameters.**
  License file: `salt = "tamga:license-file-key-v1"`, `ikm = <license key>`,
  `info = "license-file"`. Machine file: `salt = "tamga:machine-file-key-v1"`,
  `ikm = <license key>`, `info = <fingerprint>`. Both live in `Crypto/Hkdf.swift`; don't let the
  two paths bleed into each other, and don't reintroduce the pre-v2 license-file transform (raw
  key bytes zero-padded to 32). That transform and the `NaiveKey` type implementing it were
  deleted, not deprecated, so no caller can silently opt back into the weaker derivation.
- **Offline license files are format v2 only.** `alg` must be `base64+ed25519+v2` or
  `aes-256-gcm+ed25519+v2`, the payload must carry signed `meta` claims (`iat`/`exp`/`jti`/`kid`),
  and `exp` is enforced with a 60-second clock-skew tolerance
  (`LicenseFile.clockSkewToleranceSeconds`). v1 files are rejected outright with no fallback — a
  real behavioural break for anyone holding a v1 `.lic`, and the reason v2 exists: in v1 the
  expiry lived only in the envelope, so a trial file was cryptographically valid forever.
- **The license-checkout Ed25519 signature covers the base64 *string bytes* of `enc`, not its
  decoded bytes.** This is the single most common implementation bug across every Tamga SDK. See
  the `// CRITICAL:` comment in `Sources/Tamga/Checkout/LicenseFile.swift`.

## Testing

- Swift Testing (`import Testing`), **not XCTest** — this is a deliberate convention for this
  package (current idiom for Swift 5.9+/6), not a stopgap. New tests must use `@Test`/`@Suite`
  and `#expect`, not `XCTestCase`/`XCTAssert`.
- CI gates on 80% line coverage via `swift test --enable-code-coverage` →
  `xcrun llvm-cov export -summary-only` → `Scripts/check-coverage.sh`. Run the same pipeline
  locally before pushing if you're unsure a change clears the bar — see that script's header
  comment for the exact invocation.
- Three CI jobs must all pass: `swift test` on macOS, `xcodebuild test` against a fresh iOS
  Simulator device on iOS, and `swift build`/`swift test` in a `swift:6.1-jammy` container on
  Linux. The device is created at run time from whichever runtime matches the
  pinned Xcode's own default Simulator SDK (see `ci.yml`'s "Create an iOS Simulator device" step) —
  not a hardcoded device name, which proved unreliable across GitHub's runner pool. The coverage
  gate lives only in the macOS job, not the iOS one — they're intentionally not double-gated on the
  same threshold.
- Every `Tamga` type that touches the network sits behind the `HTTPRequestPerforming` protocol, and
  tests inject `MockPerformer` (`Tests/TamgaTests/Support/`). Deliberately NOT a `MockURLProtocol`
  harness: `URLProtocol` registration is unreliable on swift-corelibs-foundation and would make the
  suite Apple-only. Do not hit live network from unit tests. There is no FFI boundary to mock anymore — `Crypto/` calls
  CryptoKit/Security directly, and its own tests use real (test-generated) keys and signatures
  rather than mocking the crypto itself; see `Tests/TamgaTests/Support/` for the shared fixture
  helpers (`RsaTestKey`, `CheckoutFixture`).

## Critical Dependency Notes

- **SPM has no central package registry for this SDK** — unlike `tamga-python` (PyPI) or
  `tamga-js` (npm), there is no name-collision concern and no publish step. The git tag *is* the
  release; `release.yml` (release-please only) is the entire release surface.
- **RSA is `CryptoExtras`, not CryptoKit** — see "Crypto Architecture" above, including why the
  swift-crypto 4.x floor is load-bearing. Don't "simplify" `Crypto/Rsa.swift` by looking for a
  CryptoKit RSA type that doesn't exist.
- **`MachineAttributes` must not declare explicit snake_case `CodingKeys`.** The shared decoder
  applies `.convertFromSnakeCase`, so the two cancel: the strategy rewrites `heartbeat_status` to
  `heartbeatStatus`, lookup compares that against a CodingKey whose stringValue is
  `heartbeat_status`, matches nothing, and decodes nil. Every machine silently came back
  `.notStarted` with null timestamps. See `MachineAttributesTests`.
- **Path segments are percent-encoded by hand in `Transport`.** `URL.appendPathComponent` leaves
  both slashes and dot-segments intact, so an id of `../../evil` reached a different endpoint.
  Dots are unreserved, so escaping alone does not neutralize an all-dots segment; those get their
  dots encoded explicitly.

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/) format (`feat: …`, `fix: …`,
etc.) — `release-please` (release-type: `simple`) parses these directly to drive
`CHANGELOG.md` and version bumps. A commit that doesn't follow the convention is invisible to the
release automation, not just a style nit.
