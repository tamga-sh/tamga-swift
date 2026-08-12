# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-swift` is the official Swift SDK for Tamga, with Objective-C interoperability — license
activation and offline verification for macOS and iOS apps. It is one of two SDKs (with
`tamga-java`) that do not reimplement Tamga's cryptographic verification logic natively; instead
it binds to `tamga-c`, the Rust reference implementation exposed through a stable C ABI. Full task
breakdown and current build status: [`../docs/plans/tamga-swift.plan.md`](../docs/plans/tamga-swift.plan.md)
(lives one directory up, in the sibling `tamga-sdk` monorepo, not inside this repo).
Protocol/feature spec this SDK is built against — every field name, endpoint, and enum value comes
from here: [`tamga-api/docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md).

**Current state: business logic is still 100% stub; CI/release infra is real.** Package manifest and
module layout are in place, and CI/release infrastructure is now fully functional, not just
scaffolded — `build-xcframework.yml` really builds and publishes `TamgaCore.xcframework`, and
`release.yml`'s two-step flow really populates `Package.swift`'s binary target (see "Local
Development" and Critical Dependency Notes below). But no HTTP transport, no crypto FFI wiring, and
no business logic exists yet. Do not assume any method on `TamgaClient` does anything — see the doc
comment at the top of each stub file for what it will eventually do.

## Crypto-Boundary Rule (read before touching `Sources/Tamga/FFI/`)

Only **four** operations cross the C FFI boundary into `tamga-c`:

1. Ed25519 verify (license checkout signature check)
2. AES-256-GCM open (license file decrypt)
3. HKDF-SHA256 derive (machine file decrypt key derivation)
4. Multi-scheme verify — Ed25519/RSA-PKCS1/RSA-PSS/ECDSA-P256 (machine checkout) and RSA-PKCS1v15
   (offline proof)

**Everything else is hand-rolled, idiomatic Swift.** HTTP transport is built on `URLSession`
directly — `tamga-c` is never used for networking, JSON:API decoding, or the public client API
surface. This mirrors `tamga-java` (JNI wraps the same 4 crypto ops; the rest is plain
Java/OkHttp-equivalent). If you find yourself reaching for `CTamgaShim` outside
`Sources/Tamga/FFI/*.swift`, stop — that file is importing the C shim in the wrong layer.

## Three-Target + Binary-Target Architecture

```
tamga-swift/
├── Package.swift                — SPM manifest: 5 targets + 1 binary target
├── Sources/
│   ├── CTamgaShim/               — C target: makes tamga.h Swift-importable
│   │   └── include/
│   │       ├── module.modulemap
│   │       └── shim.h            — real re-export of tamga.h (tamga-c has shipped v1.0.0/v1.0.1)
│   ├── Tamga/                    — public Swift API (depends on CTamgaShim only for crypto)
│   │   ├── TamgaClient.swift     — top-level client: config, all endpoint methods
│   │   ├── Transport.swift       — URLSession-based HTTP layer, auth headers, content-type dispatch
│   │   ├── Errors.swift          — TamgaError enum, JSON:API error envelope decoder
│   │   ├── Proof.swift           — offline proof generate/verify
│   │   ├── FFI/                  — CTamgaShim wrappers; the ONLY files that import CTamgaShim
│   │   ├── Models/                — ValidationCode, License, Machine, Policy, ...
│   │   └── Checkout/               — LicenseFile, MachineFile (PEM parse/verify/decrypt)
│   └── TamgaObjC/                — thin Objective-C interop wrapper over Tamga
├── Tests/TamgaTests/             — Swift Testing (import Testing, NOT XCTest)
├── Scripts/check-coverage.sh     — hand-written 80% line-coverage gate for CI
└── .github/workflows/
    ├── ci.yml                    — swiftlint + swift test (macOS) + xcodebuild test (iOS)
    ├── build-xcframework.yml     — workflow_call → tamga-c build-native.yml → zip → checksum → gh release upload
    └── release.yml               — release-please + post-release Package.swift bot-commit
```

`tamga-web`-equivalent: there is no server here. `Tamga` is the library target apps link against;
`TamgaObjC` is a thin wrapper for Objective-C-only consumers, not a separate implementation.

## Local Development

`Package.swift`'s `binaryTarget(url:checksum:)` is populated automatically by `release.yml`'s
post-release bot commit (see that file's header comment) once `tamga-c` has released and
`build-xcframework.yml` has run — `tamga-c` has shipped tagged releases (v1.0.0, v1.0.1) and this
pipeline is real, not a placeholder. If you need to iterate locally against a `tamga-c` checkout
that hasn't been released yet (e.g. testing an unreleased `tamga-c` change end-to-end before cutting
a release), build `tamga-c`'s XCFramework locally and swap the binary target:

```swift
// Comment out the url:/checksum: binaryTarget in Package.swift and use:
.binaryTarget(
    name: "TamgaCore",
    path: "../tamga-c/build/TamgaCore.xcframework"
),
```

This requires a sibling checkout of `tamga-c` with its XCFramework already built locally. Do not
commit the `path:` variant — it only works on a machine with that sibling checkout present. Revert
to the `url:`/`checksum:` form before pushing.

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

**First-time setup**: since `tamga-c` has no release yet, `swift build`/`swift test` will fail to
resolve `TamgaCore` out of the box. Apply the local-dev `path:` override above against a locally
built `tamga-c` XCFramework before anything else will compile.

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
- Two CI jobs must both pass: `swift test` on macOS, `xcodebuild test -destination 'platform=iOS
  Simulator,name=iPhone 16'` on iOS. The coverage gate lives only in the macOS job, not the iOS
  one — they're intentionally not double-gated on the same threshold.
- Every `Tamga` type that touches the network or FFI must sit behind a protocol for test doubles
  (mock `URLSession` via a `MockURLProtocol` harness, mock FFI verifier) — see the
  `ecc:swift-protocol-di-testing` skill. Do not hit live network or call into the real
  `CTamgaShim`/`TamgaCore` binary from unit tests.

## Critical Dependency Notes

- **`tamga-c`'s ABI-freeze commitment still governs `shim.h`, but is no longer a blocker.** `tamga-c`
  has shipped tagged releases (v1.0.0, v1.0.1) with a frozen `tamga.h`, and
  `Sources/CTamgaShim/include/shim.h` is now a real re-export (`#include <tamga.h>`) rather than a
  stub — see that file's own header comment. The constraint that still applies going forward: struct
  layout and function signature changes in `tamga.h` require a version bump on `tamga-c`'s side, no
  silent breaking changes — do not hand-transcribe `tamga.h` declarations into `shim.h` by hand even
  now, the `#include` is what keeps this file from ever drifting from `tamga-c`'s actual ABI.
- **SPM has no central package registry for this SDK** — unlike `tamga-python` (PyPI) or
  `tamga-js` (npm), there is no name-collision concern and no publish step. The git tag *is* the
  release; `release.yml` and `build-xcframework.yml` are the entire release surface.
- **Binary-target chicken-and-egg**: `Package.swift`'s checksum can't be computed before the
  XCFramework asset exists, and the asset can't exist before the tag does. This is why release
  automation is two workflows, not one — see `release.yml`'s header comment for the full
  explanation before "simplifying" it into a single job.

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/) format (`feat: …`, `fix: …`,
etc.) — `release-please` (release-type: `simple`) parses these directly to drive
`CHANGELOG.md` and version bumps. A commit that doesn't follow the convention is invisible to the
release automation, not just a style nit.
