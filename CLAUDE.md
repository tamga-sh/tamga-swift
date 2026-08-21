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
(`TamgaClient`'s 35 methods, `Transport`, `AuthTransport`, the JSON:API error model,
`EntitlementCache`, both heartbeat schedulers, and the full `Policy` struct) are all implemented
and tested — 381 tests, ~94.6% line coverage against an 80% gate. (The method count read "31"
before this was recounted mechanically at `git grep -c '^    public func ' Sources/Tamga/TamgaClient*.swift`;
it was 32 on the previous release and three artifact reads were added on top.)

Deliberately **not** wrapped: a machine's `group`/`owner` sub-resources
(`GET|PATCH /machines/{id}/{group,owner}`), which return `groups` and `users` resource types this
SDK models nowhere else and which are an admin-console concern; and artifact **writes**
(`artifact.create`/`update`/`delete`), which are absent from `Role::LicenseToken` — publishing is
an operator action, not a client one.

Artifact **read and download** are wrapped as of `tamga-api@e6d317b`, which added `artifact.read`
and `artifact.download` to `Role::LicenseToken` (`shared/authz/mod.rs:263-264`) and routed a real
handler. The previous entry here — that download `403`s for every client because no role grants
the action — was true when written and is now stale; see the artifact bullet under "Endpoint
notes".

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

**`Crypto/Ecdsa.swift` accepts a bare 65-byte uncompressed point as well as SPKI, and it has to.**
The server publishes `ecdsa_public_key` as `BASE64.encode(ecdsa_pair.public_key().as_ref())`
(`crypto/key_material.rs`, pinned by its own `ecdsa_public_key_is_65_bytes` test) and
`accounts/serializer.rs` hands that same string to API callers. This type used to require X.509
`SubjectPublicKeyInfo` and so returned `false` for every genuine ECDSA machine file — a caller who
base64-decoded the key the API gave them could not verify anything. Confirmed empirically against
server-issued fixtures. The whole SDK fleet assumes PKIX/SPKI here, so the same gap is very likely
live in the other seven repos. RSA needs no equivalent branch: the server publishes PKCS#1
`RSAPublicKey` DER and `_RSA.Signing.PublicKey(derRepresentation:)` accepts both encodings.

**`Crypto/Ecdsa.swift` has an explicit curve-OID check, and it is worth less than it used to claim.**
Confirmed directly (empirically, not assumed): CryptoKit's
`P256.Signing.PublicKey(derRepresentation:)` does NOT validate the curve OID in the
`AlgorithmIdentifier` it parses. A hand-crafted SPKI declaring the secp256k1 curve OID but carrying
a real P-256 point's raw coordinates is silently accepted by CryptoKit's own parser, and
`Ecdsa.swift`'s guard (backed by `DER.swift`'s minimal OID extractor) is what rejects it.

**But this guard is not what stops a foreign-curve signature verifying, and the note here used to
say it was.** Measured against the pinned swift-crypto 4.5.1, a key on a genuinely different curve
is refused by BOTH branches on POINT VALIDITY before any OID is read — a real secp256k1 SPKI and a
real secp256k1 bare point are each rejected because the coordinates do not satisfy P-256's curve
equation (BoringSSL's `EC_KEY_check_key`, reached from both initializers). And `verify` is
hardcoded to build a `P256.Signing.PublicKey`, so the curve the math runs on is fixed at compile
time and the key cannot choose it. What the OID check genuinely rejects is a *mislabelled* key: a
real P-256 point wearing another curve's OID, which is a valid P-256 key that would verify
correctly. Refusing it is hygiene — a key whose own metadata contradicts itself is not trustworthy —
not forgery prevention.

Keep it anyway. It is cheap, and it is the standing guard on this type never growing a dynamic
multi-curve dispatch — which is precisely the shape in which this bug class IS a live forgery risk
in `tamga-python`/`tamga-go`/`tamga-dotnet`'s generic `ECDsa`-based verifiers, where the key really
does select the curve. Do not "unify" the two branches by dropping it, and do not restate the
overbroad version of this claim. `EcdsaTests.swift` covers both branches with real
P-384/secp256k1 keys; note that a P-384 point is 97 bytes and so never reaches the 65-byte
bare-point branch at all — secp256k1 is the curve that tests it.

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
│   │   │                            (+Machines, +Entitlements, +Reads, +Reactivation,
│   │   │                             +Releases, +Health)
│   │   ├── Transport.swift       — HTTPRequestPerforming seam, URL/auth/headers, 429 retry
│   │   ├── Transport+Helpers.swift — the pure half: version sanitizing, path encoding, backoff
│   │   ├── AuthTransport.swift   — the seven auth forms
│   │   ├── EntitlementCache.swift, HeartbeatScheduler.swift — actors
│   │   ├── Errors.swift          — TamgaError (API) and TamgaCheckoutError (offline)
│   │   ├── APIErrorCodes.swift   — TamgaAPIErrorCode constants + limit-code normalization
│   │   ├── Proof.swift           — MachineProof: offline proof parse/verify
│   │   ├── CanonicalJson.swift   — recursive alphabetical-key-sorted JSON writer, for Proof
│   │   ├── Crypto/                — Ed25519, AesGcm, Hkdf, Ecdsa, Rsa, DER — see "Crypto Architecture" above
│   │   ├── Models/                — License, Machine, Component, MachineProcess, Entitlement,
│   │   │                             Policy, Release, HealthStatus, Scope, ValidationCode/Meta,
│   │   │                             Page (keyset) + OffsetPage (machines only), requests/results
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

- **The auto-update endpoint works, and its `204` means two things.** `GET
  /releases/actions/upgrade` routes to a live handler and is **public** (optional auth); it is
  wrapped as `checkForUpgrade`. Four query parameters are REQUIRED — `product` (the product
  **UUID**, not its code), `platform`, `filetype`, `version` — and axum's plain `Query` extractor
  rejects a missing one with a **plain-text 400**, not a JSON:API error document, so the code
  degrades to the synthetic `UNKNOWN`. Optional: `constraint` (omitting it defaults to patch-only
  `~x.y.z`, not "any newer") and `channel` (omitting it matches **every** channel including
  `alpha`/`dev`). `204 No Content` is returned both when there is no newer release and when there
  IS one the licence is not entitled to — deliberately, so a denial cannot leak "a newer version
  exists but you cannot have it". Never report it as "up to date"; `UpgradeCheckResult` names the
  case `.noneAvailable` for that reason. A **suspended** licence gets `403` instead, before the
  204 branch.
- **Artifacts are readable and downloadable with a licence key, and the download does NOT stream
  bytes.** `artifact.read`/`artifact.download` were added to `Role::LicenseToken` in
  `tamga-api@e6d317b`; before that every call was a `403` and this SDK deliberately wrapped
  nothing. Three routes: `GET /releases/{release_id}/artifacts` (keyset, real `(created_at, id)`
  seek, so `synthesizeCursor` is sound here unlike for entitlements), `GET /artifacts/{id}`, and
  `GET /artifacts/{id}/actions/download`. Three things to keep straight:
  1. **The download answers `303 See Other`** to a presigned storage URL by default. Following it
     with the `Authorization` header attached hands the licence key to the storage host, so
     `downloadArtifact` sends `?redirect=false` and gets the resource back with `redirectUrl`
     populated instead. The `URLSession` layer refuses redirects anyway
     (`SessionPolicyDelegate.urlSession(_:task:willPerformHTTPRedirection:…)` →
     `completionHandler(nil)`), verified against a real socket for `303` specifically with the
     redirect target asserted to have accepted zero connections. The returned URL must be fetched
     with **no** credentials, and not through `Transport` — a real artifact routinely exceeds the
     32 MiB response cap.
  2. **`ArtifactAttributes` is `rename_all = "camelCase"` AND carries explicit
     `#[serde(rename = "created")]`/`"updated"`** (`artifacts/serializer.rs:20,34-37`). So the wire
     is `redirectUrl` but `created`/`updated` — **not** `createdAt`/`updatedAt`. The shared decoder's
     `.convertFromSnakeCase` leaves every one of those alone, so `ArtifactAttributes` declares no
     `CodingKeys`; adding them would compare a snake_case `stringValue` against the already-converted
     key and decode `nil`, which is the bug `MachineAttributes` shipped. Measured side effect of
     leaving them off: `redirect_url` decodes too, so a server-side rename either way is a non-event.
  3. **A `403` on download is not necessarily an auth misconfiguration.** The handler runs
     `releases::service::enforce_release_access` after the permission check, so the product's
     distribution strategy, licence suspension, licence expiry under the policy's
     `expirationStrategy`, and release entitlement each answer `403` to a caller that does hold
     `artifact.download`. Listing does **not** apply that gate (`list_artifacts` calls
     `require_read` only), so a listable artifact is not necessarily a downloadable one.
- **`/v1/health` must be called anonymously, and the reason is a middleware ordering bug-shaped
  behaviour.** `require_authentication` (`auth/require_auth.rs:120-127`) resolves the request's
  credential with `?` **before** it uses the `is_public_route` result it computed one line earlier,
  so a resolution *error* rejects a public route. Whether resolution runs at all on a path with no
  `{account_id}` depends on the mode: multiplayer short-circuits to `Ok(None)`
  (`auth/context.rs:293-297`), but **singleplayer is `#[default]`** (`config.rs:11-12`) and takes
  the account id from configuration, so the lookup runs for every path — and a licence key under a
  default policy returns `Err(401 LICENSE_NOT_ALLOWED)` (`auth/license_lookup.rs:83-84`). Sending a
  credential would therefore break the probe for exactly the callers it exists to help.
  `Transport.RouteScope.publicRoot` encodes this; do not "fix" it into sending auth for
  consistency with the fleet contract's §2.
- **`GET /policies/{id}` is unreachable under licence-key auth; `GET /licenses/{id}/policy` is not.**
  The first asks for `policy.read`, which is absent from `Role::LicenseToken`'s permission set
  (`authz/mod.rs:236-261`); the second asks for `license.read`, which is present. Both are wrapped
  (`getPolicy`, `getLicensePolicy`) and each one's doc points at the other. Do not collapse them.
- **Nothing licence-scopes the licence and machine routes.** `require_license_scope` is called
  only from the four validate/checkout handlers. `GET /licenses/{id}` returns `attributes.key` in
  cleartext and gates only on `license.read`; the machine routes gate on `machine.read`/`.update`/
  `.delete`, all of which `Role::LicenseToken` holds by default. So a licence key can read any
  licence in the account (key included) and update or delete any machine in it. Filed upstream —
  do not write docs implying that surface is scoped, and do not try to "fix" it client-side.
- **The machine collection is OFFSET-paginated; its sub-collections are not.** `GET /machines`
  emits `meta.page{number,size,total,totalPages}` and takes `page[number]`/`page[size]` (aliases
  `page`/`limit`). `GET /machines/{id}/components` and `/processes` take bare `limit` plus
  `page[after]` and emit no `meta` at all. Do not unify them. `GET /machines` has **no fingerprint
  filter** — `filter[q]` is `%term%` ILIKE across `name`/`hostname`/`fingerprint`, truncated at
  200 chars; multi-value filters are comma-joined inside one value, because a repeated key
  silently collapses to its last occurrence.
- **A machine resource carries no `license_id` and no `relationships`.** No serializer in the API
  emits a relationships block. So nothing client-side can tell which licence a machine belongs to,
  which is why `reactivateMachine`'s fingerprint lookup is account-wide and why
  `Scope(fingerprint:)` is the only membership check available.
- **The process reaper is dead code.** No server job deletes a process row, ever, and processes
  count against `policy.max_processes`. `deleteProcess` / `ProcessHeartbeatScheduler.stopAndDelete`
  are the only things that clean up.
- **Auth IS enforced server-side, and license-key auth is off by default.** The old "no auth is
  enforced" note was false. `Authorization: License <key>` only authenticates when the license's
  policy sets `authentication_strategy` to `LICENSE` or `MIXED`; the column defaults to `'TOKEN'`,
  and `NONE` behaves like `TOKEN` at that gate. Against a default policy every license-key call
  fails `401 LICENSE_NOT_ALLOWED` — a policy configuration precondition, not a retryable auth
  failure. Separately, an expired license still authenticates under three of the four expiration
  strategies and only fails `401 LICENSE_EXPIRED` under `REVOKE_ACCESS`.
- **16 of 24 `ValidationCode` values are reachable.** Model all 24 with lenient/unknown-value
  decoding, but don't build UI/UX around the 8 that are declared and never emitted
  (`BANNED`, `TOO_MANY_USERS`, `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`,
  `COMPONENTS_SCOPE_MISMATCH`, `CHECKSUM_SCOPE_MISMATCH`, `VERSION_SCOPE_MISMATCH`, and
  `NOT_FOUND` which surfaces as an HTTP 404 instead of this code). `ENTITLEMENTS_MISSING` and
  `FINGERPRINT_SCOPE_MISMATCH` moved onto the reachable side — see the `Scope` bullet below.
- **`Scope`: six fields enforced, two that break the call.** `product`/`policy`/`user`/
  `environment` were always enforced; `entitlements` and `fingerprint` now genuinely are.
  `entitlements` takes entitlement **codes** (not the attach/detach UUIDs), compared
  case-insensitively after de-duplication, satisfied by direct *and* policy-inherited rows, and an
  empty array asserts nothing. `fingerprint` matches any machine row on the license regardless of
  heartbeat status. `version` and `checksum` are worse than ignored: either one present makes the
  server reject the **whole validate call** with `422 SCOPE_NOT_SUPPORTED`, so `Scope.requestValue`
  no longer emits them. Do not add a typed `SCOPE_NOT_SUPPORTED` case to `TamgaError` — the enum is
  public and exhaustive; map it through `.api` and `TamgaAPIErrorCode`.
- **429 handling covers seven safe `POST` actions, not five.** `429 TOO_MANY_REQUESTS` is live
  server-side. `Transport` parses `Retry-After` and caps it, backs off with jittered exponential
  delays, and scopes auto-retry to `GET` plus `validate`, `validate-key`, `check-in`, `check-out`,
  `ping`, `ping-heartbeat` and `reset-heartbeat`. The last two were wrongly excluded: both are bare
  idempotent state writes, the rate limiter buckets per route pattern (so a whole fleet shares one
  `ping-heartbeat` budget and throttles itself), and a dropped heartbeat pushes the machine past
  its window.
  Creates stay excluded — retrying one risks a duplicate resource and a burnt seat.
- **Machine creation enforces limits too, and which check fires is the policy's choice.** The
  create-time check runs through the overage strategy: under `NO_OVERAGE` an over-limit `POST
  /machines` is refused `422` with `MACHINE_LIMIT_EXCEEDED`/`CORE_LIMIT_EXCEEDED`/
  `MEMORY_LIMIT_EXCEEDED`/`DISK_LIMIT_EXCEEDED`, while under `ALLOW_ACCESS`/`ALLOW_1_25X_OVERAGE`
  it succeeds and the limit surfaces at validate time as `TOO_MANY_*`/`TOO_MUCH_*`.
  `activateMachine` must handle **both**: normalize the create-time code onto the `ValidationCode`
  vocabulary and throw `.machineOverLimit` with no rollback (no row was written), and keep the
  create→validate→delete rollback for the overage path.
- **Machine `memory` and `disk` are MEGABYTES, not bytes.** Reporting 16 GB as `17179869184`
  inflates the license's `machines_memory_count` by 1,048,576× and trips `MEMORY_LIMIT_EXCEEDED`
  on the next activation against that license.
- **`page[after]` is inert on `/licenses/{id}/entitlements`.** The listing unions direct and
  policy-inherited rows, so the server dropped the keyset predicate and accepts the parameter only
  for wire compatibility — a cursor loop refetches page one forever. `listEntitlements` must
  return `nextCursor: nil` unconditionally and must not send the parameter. `limit` clamps to 100,
  which is a hard ceiling: a license with more than 100 effective entitlements cannot be enumerated
  in full. `/machines/{id}/components` is different — keyset works there, don't "fix" it.
- **Omitting `limit` truncates silently at 25.** Nested list routes emit neither `meta.page` nor
  `links`, so page fullness is the only pagination signal and it can't be read without knowing the
  page size that was requested. Always send an explicit `limit`.
- **Quick-validate DOES touch the license — unless the request carries `Origin`.** The doc comment
  used to claim the opposite. `GET /licenses/{id}/actions/validate` writes `last_validated_at` on
  every call except when an `Origin` header is present, and the response is byte-identical either
  way. It has no `skip_touch`; the only side-effect-free route is `POST validate` with
  `meta.skip_touch: true`. A proxy injecting `Origin` silently disables the write, which keeps a
  license reporting `INACTIVE` and the check-in-overdue worker firing forever.
- **`resetHeartbeat` and `generateOfflineProof` always 403 under a license key.** Both are gated on
  the caller's *role* (admin/developer/product/environment token), not on a permission, and a
  license-scoped credential is in neither set — `generateOfflineProof` despite holding the
  `machine.proofs.generate` permission. Don't present either as a recovery path to an embedded
  client.
- **`expiration_strategy` has four values and `authentication_strategy` has four.**
  `RESTRICT_ACCESS` (default), `MAINTAIN_ACCESS`, `ALLOW_ACCESS`, `REVOKE_ACCESS`; and `TOKEN`
  (default), `LICENSE`, `MIXED`, `NONE`. `REVOKE_ACCESS` and `NONE` were both missing here. See
  `Models/Policy.swift`'s `ExpirationStrategy`/`AuthenticationStrategy` constants.
- **Don't set the SDK's default timeout to the server's.** The server's `TimeoutLayer` is 30s; an
  equal client deadline races it and usually wins, throwing away the server's `504` and the
  `x-request-id` that is the only correlation handle for a slow-request report.
- **`Tamga-Environment` request header does nothing server-side.** It's a planned EE feature with
  no request-parsing code path yet. Don't expose a client-facing "environment" request option that
  implies it's honored today.
- **Fresh policies default to non-existent enum variants.** `overage_strategy` defaults to the
  literal string `"DENY_ACCESS"` and `heartbeat_resurrection_strategy` to `"NO_RESURRECTION"` —
  neither is a real variant of `OverageStrategy`/`HeartbeatResurrectionStrategy`. The server
  silently treats both as the "no restriction" variant (`NO_OVERAGE`/`NO_REVIVE`). Decoders here
  must not crash on these strings, and must not invent fake enum cases that imply restrictive
  behavior the server doesn't actually have.
- **The machine heartbeat window is policy-driven; only the process window is hardcoded.** The
  machine window is `policy.heartbeat_duration`, with 600s as the fallback for a null column —
  `Policy::effective_heartbeat_duration_secs` and the cull job's `COALESCE(p.heartbeat_duration,
  600)` agree on that, and `heartbeat_status`/`next_heartbeat_at` are both computed from it. The
  process heartbeat window really is a hardcoded 30s, with no resurrection grace period at all.
  `HeartbeatScheduler.window`/`defaultInterval` are still sized against the 600s fallback, but
  `HeartbeatScheduler.sizedToPolicy(client:machineId:licenseId:)` now reads the window off
  `getLicensePolicy` and sizes the interval from it — that is the right default on any policy that
  sets a shorter window. No field carries the window outright, and `Machine.nextHeartbeatAt` only
  half-substitutes: `create`, `ping-heartbeat`, `reset-heartbeat` and **`PATCH`** return the
  written row without the policy join, so there it is `last_heartbeat_at + 600s` whatever the
  policy says, while `GET /machines/{id}`, the machine list, check-out and offline-proof all derive
  it from the policy. Two responses for the same machine can disagree; do not size an interval
  from it. ⚠️ **Both schedulers floor the interval at one second** (`flooredInterval`), which is a
  bound on the request rate rather than the non-positive guard it replaced — `Task.sleep` honours a
  sub-second delay exactly, so `0.001` really does issue ~665 pings a second, and a guard that
  clamps `0` while passing `0.001` bounds nothing. Do **not** narrow it back. The floor costs
  nothing a policy can express, because liveness is judged on *truncated* whole seconds:
  `heartbeat_status_within` compares `(now - last).num_seconds() <= window_secs` and
  `num_seconds()` truncates, so a machine first reads `DEAD` at `window_secs + 1` and every window
  carries a free second. Do not restate that pessimistically as "DEAD once age passes the window" —
  that reading makes a 1s window look unserveable at a 1s ping when it has 2s of slack. What the
  floor does cost is the divisor's two-losses promise (window 3 agrees, 2 keeps one spare, 1 keeps
  none), and the window no interval can hold is **`0`**, not `1`. Because `0` is unholdable at any
  rate, `interval(forWindowSeconds:)` substitutes the 600s fallback **window** for a non-positive
  one *before* dividing — same `.dead` verdict, 200× fewer requests than flooring the divided `0`
  to 1s would give. Keep `windowSeconds(for:)` faithful regardless; reporting the window and
  scheduling against it are different jobs. Do not add a window-aware floor to chase `0`; the
  table in `HeartbeatFloorTests` and its standing caveat are the record.
- **`DEAD` is not reachable from a ping.** Every write route returns a status that cannot be it:
  `ping-heartbeat` sets `last_heartbeat_at = NOW()` and `heartbeat_status_within` then measures
  `Utc::now() - last_heartbeat_at` against the window (`machines/model.rs:124-146`), so it is always
  `ALIVE` or `RESURRECTED`; `reset-heartbeat` nulls the column and `POST /machines` never sets it,
  so both are `NOT_STARTED`; and `validate` never constructs `ValidationCode::HeartbeatDead` — the
  variant exists in `licenses/model.rs:201` with zero construction sites. `DEAD` is served from
  anything that reads the stored row: `check-out`, `generate-offline-proof`, and now
  `GET /machines/{id}` and `GET /machines`, all wrapped here. **`PATCH /machines/{id}` is the
  counterexample to the route-shaped version of this rule** — it is a write, but it never touches
  `last_heartbeat_at`, so it judges an untouched timestamp and can answer `DEAD`. State the rule as
  *what the response was built from*, never as a list of write routes. Do not write a `DEAD` branch
  against a ping response — it is unreachable — and do not delete the enum case or the field.
- **`DEAD` would not mean the row was culled either, and on a default policy nothing is ever
  culled.** `require_heartbeat` defaults to `FALSE`, the cull job early-returns for any policy that
  does not set it, and `Machine::heartbeat_status*` never consults the flag at all — it derives
  `DEAD` purely from `last_heartbeat_at` against the window. So a machine reads `DEAD` *forever*
  while its row and its seat are still there, and a ping against it succeeds and revives it: the
  update is a bare `SET last_heartbeat_at = NOW()` with no resurrection check. State the rule
  positively: a scheduler must not stop on *any* status, expected or not. The only terminal signal
  from a ping is a `404 NOT_FOUND`, and re-activation should hang off that
  (`TamgaError.isNotFound`). Do not reintroduce the old "DEAD means re-activate, don't keep
  pinging" guidance; it is the bug `tamga-python` shipped.
- **Both file types derive their AES key with HKDF-SHA256, but never with the same parameters.**
  License file: `salt = "tamga:license-file-key-v1"`, `ikm = <license key>`,
  `info = "license-file"`. Machine file: `salt = "tamga:machine-file-key-v1"`,
  `ikm = <license key>`, `info = <fingerprint>`. Both live in `Crypto/Hkdf.swift`; don't let the
  two paths bleed into each other, and don't reintroduce the pre-v2 license-file transform (raw
  key bytes zero-padded to 32). That transform and the `NaiveKey` type implementing it were
  deleted, not deprecated, so no caller can silently opt back into the weaker derivation.
- **Offline MACHINE files are format v2 too, and the SDK used to read all three parts of that
  format wrong.** `alg` is `"<encoding>+<signing suffix>+v2"`, parsed by `MachineFileAlgorithm`:
  encoding at the FIRST `+`, the `v2` marker at the LAST, signing suffix in between, cross-checked
  against the caller-supplied scheme. Both `aes-256-gcm` and `rsa-pss-sha256` contain hyphens and
  `rsa-pss-sha256` contains `rsa-sha256`, so a substring test or an index-1 split gets `ed25519`
  right and the rest wrong — which is why the bug survived. `alg` is NOT covered by the signature,
  so a downgrade to v1 costs an attacker one edit. An encrypted machine file's `enc` is
  `"<nonce_b64>.<cipher_b64>"` — two SEPARATELY base64'd halves, from
  `FieldEncryption::encrypt` — not one blob with a 12-byte nonce on the front. (The server's own
  doc comment at `machine_file.rs` still says `base64(nonce‖ciphertext‖tag)` and contradicts the
  code twenty lines below it; that stale comment is why all eight SDKs implemented the same wrong
  thing. Trust the code.) LICENSE files really are the single-blob form — `encode_license_file`
  does not go through `FieldEncryption` — so `EncryptedPayloadDecryptor` keeps both readers and
  they are not interchangeable. **Whether that misreading was an ACTIVE failure depended on the
  language's base64 decoder, and Swift is on the failing side.** Both halves are a multiple of 4
  characters, so a lenient decoder drops the `.`, decodes the concatenation as one stream, and
  reconstructs `nonce ‖ ciphertext ‖ tag` byte-for-byte — the old 12-byte slice then lands
  correctly by accident, which is what happens in CPython and Node. `Data(base64Encoded:)` is
  strict unless given `.ignoreUnknownCharacters`, and no call site here passes it, so every
  encrypted machine file failed outright with "enc is not valid base64". Do not add that option to
  "be forgiving": it would quietly restore the wrong reading.
  `MachineFileServerFixtureAdversarialTests.dotSeparatedEncIsNotAcceptedAsPlainBase64` is the
  standing guard on that. And the signed payload carries `meta` claims, so `exp` is enforced
  with the SAME `LicenseFile.clockSkewToleranceSeconds`; a missing `exp` is legitimate and means
  the checkout carried no `ttl`. Verify, then split, then decode, then decrypt — never decode
  attacker-controlled bytes before the signature has passed.
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
