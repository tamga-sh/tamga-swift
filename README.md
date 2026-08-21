# Tamga

Official Swift SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Swift applications.

Two independent surfaces, either usable without the other:

- **`TamgaClient`** talks to the API — validation, activation, checkout, heartbeats, components,
  processes and entitlements. Twenty `async` endpoints, seven auth transports, and automatic
  handling of HTTP 429.
- **`LicenseFile`, `MachineFile` and `MachineProof`** verify `.lic`/`.machine` files and offline
  proofs with **no network access at all**, once your account's public key is embedded in the app.

Runs on macOS 13+, iOS 16+ and Linux. 256 tests, with an 80% line-coverage gate in CI.

## Install

Swift Package Manager, by git URL — SPM resolves packages by URL, and Tamga publishes no
central-registry package name:

<!-- x-release-please-start-version -->
```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/tamga-sh/tamga-swift", from: "1.3.1"),
]
```
<!-- x-release-please-end -->

Then add the `Tamga` product to your target:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "Tamga", package: "tamga-swift"),
    ]
)
```

Requires a Swift 6.0 toolchain, macOS 13+ or iOS 16+.

## Quickstart

Verify a license file that was checked out for a given license key. `parse` reads the PEM
envelope, `verifyAndDecrypt` checks the Ed25519 signature, enforces the file's signed expiry, and
decrypts the payload:

```swift
import Foundation
import Tamga

func activate(licenseFile pem: String, licenseKey: String, publicKey: Data) {
    do {
        let license = try LicenseFile.parse(pem)
            .verifyAndDecrypt(publicKey: publicKey, licenseKey: licenseKey)
        print("Verified license \(license.id); suspended: \(license.suspended)")
    } catch TamgaCheckoutError.expired(let exp) {
        print("License file expired at \(Date(timeIntervalSince1970: TimeInterval(exp)))")
    } catch TamgaCheckoutError.signatureVerificationFailed {
        print("Signature check failed — this file is forged or corrupted")
    } catch {
        print("License file could not be read: \(error)")
    }
}
```

`publicKey` is your account's raw 32-byte Ed25519 public key, shipped inside your app. Every
failure is a case of [`TamgaCheckoutError`](Sources/Tamga/Errors.swift); nothing here silently
returns an unverified `License`.

## Release artifacts

An artifact is the payload of a release — the file an updater actually downloads. These became
reachable from a licence key in `tamga-api@e6d317b`, which granted `artifact.read` and
`artifact.download` to the licence-token role; before that every call was a `403` and this SDK
wrapped nothing.

```swift
let page = try await client.listReleaseArtifacts(releaseId: release.id)
guard let artifact = page.items.first(where: { $0.platform == "darwin" && $0.arch == "arm64" })
else { return }

let download = try await client.downloadArtifact(artifact.id, ttl: 900)

// A plain session. NOT the SDK's client, and no Authorization header.
let (fileURL, _) = try await URLSession.shared.download(from: download.url)
```

**The URL is fetched by you, without credentials, and that is the whole design.** The route's
default answer is a `303 See Other` pointing at object storage; following it with this client's
`Authorization` header still attached would hand your license key to the storage host. So
`downloadArtifact` asks for `?redirect=false` and gets the presigned URL back in the body instead.
The URL authenticates itself through its query string and needs no header of yours. Nothing is
streamed through the SDK — a real installer routinely exceeds the client's 32 MiB response cap, and
`Artifact.checksum` is yours to verify against the bytes you receive.

`ttl` is the URL's lifetime in seconds, between `TamgaClient.minimumDownloadTTLSeconds` (60) and
`TamgaClient.maximumDownloadTTLSeconds` (604800, one week). Omit it for the server's 300-second
default. Out-of-range values are refused before the request is sent.

**A `403` here is usually not a permissions problem.** The download enforces the owning release's
read gate as well as the permission, so a product's `CLOSED` distribution strategy, a suspended
license, an expired license under a policy whose `expirationStrategy` withholds newer builds, and a
missing release entitlement each answer `403` to a caller that *does* hold `artifact.download`.
Listing does not apply that gate, so a listable artifact is not necessarily a downloadable one.

`Artifact.redirectURL` is `nil` on list and show — the server omits the key there. Use
`downloadArtifact`, which returns the URL parsed and non-optional.

## Fingerprint canonicalisation

The server stores `fingerprint TEXT NOT NULL` with no length limit, no `CHECK` and no
normalisation, unique per `(license_id, fingerprint)`. So `"ABC-123"`, `"abc-123"` and
`" ABC-123 "` are three machines occupying three seats on one license. `TamgaFingerprint` collapses
the differences that are accidents of formatting, and only those:

```swift
let fingerprint = try TamgaFingerprint.compute([
    .init(label: "machine-id", value: machineId),
    .init(label: "disk", value: diskSerial)
])
let machine = try await client.activateMachine(
    licenseId: licenseId, options: .init(fingerprint: fingerprint))
```

The rule, identical in all eight SDKs:

```text
canonical   = "tamga-fingerprint-v1" <US> join(<US>, sort_bytewise(["label=value"]))
fingerprint = lowercase_hex(SHA-256(UTF-8(canonical)))     // 64 characters
```

`<US>` is U+001F. Component order does not matter (they are sorted). Surrounding ASCII whitespace
is trimmed from values. Labels must be non-empty ASCII printable `0x21`–`0x7E` without `=`; values
may contain `=`, non-ASCII text, or nothing at all.

Three things it deliberately does **not** do, each of which throws or is documented rather than
being quietly applied:

- **No Unicode normalisation.** Foundation offers `precomposedStringWithCanonicalMapping` and using
  it here would be one line. It is left out because NFC needs a new dependency in Rust and Go and
  ICU or hand-rolled tables in C11 — and a rule eight ports cannot implement identically is worse
  than no rule, because it would give one machine two fingerprints depending on which SDK the app
  was written in. **If your values can arrive in more than one normal form, normalise them
  yourself before calling.**
- **No case folding.** Lowercasing a base64 or hex identifier corrupts it.
- **No repair.** An empty label, a duplicate label, a non-ASCII label, a control character in a
  value, or an empty component list all throw
  [`TamgaFingerprintError`](Sources/Tamga/Fingerprint.swift). Stripping a control character instead
  would map two different inputs onto one seat.

`TamgaFingerprint.canonical(_:)` returns the pre-hash string, which is worth logging when two
machines disagree — a 64-character hash says nothing about which component differed.

## Offline verification

### License files (`.lic`)

`verifyWithClaims` is the full form: it returns the signed claims alongside the license and takes
the current time from you, so an app that keeps a server-supplied timestamp can verify against
that rather than a clock the user controls.

```swift
import Foundation
import Tamga

func claims(for pem: String, licenseKey: String, publicKey: Data, serverNow: Int64) throws {
    let (license, claims) = try LicenseFile.parse(pem).verifyWithClaims(
        publicKey: publicKey,
        licenseKey: licenseKey,
        now: serverNow
    )

    print("license \(license.id), issued at \(claims.iat), checkout id \(claims.jti)")
    if let exp = claims.exp {
        print("expires at \(exp)")
    } else {
        print("no ttl was requested at checkout — this file does not expire")
    }
}
```

**Format v2 is required.** A `.lic` file's `alg` must be `base64+ed25519+v2` or
`aes-256-gcm+ed25519+v2`, and its payload must carry the signed `meta` claims (`iat`, `exp`,
`jti`, `kid`). v1 files are rejected outright, with no fallback path — if you hold files issued
before v2, re-issue them. See [SECURITY.md](SECURITY.md#offline-license-file-format-v2-compatibility-warning)
for why the break was worth it.

### Machine files (`.machine`)

Machine files are signed with the license's own scheme, and you pass that scheme in — the file's
self-declared `alg` is never trusted to pick the verifier. Decryption needs both the license key
and the fingerprint of the machine the file was issued for:

```swift
import Foundation
import Tamga

func verifyMachineFile(
    _ pem: String,
    scheme: LicenseScheme,
    publicKey: Data,
    licenseKey: String,
    fingerprint: String
) throws -> Machine {
    try MachineFile.parse(pem).verifyAndDecrypt(
        scheme: scheme,
        publicKey: publicKey,
        licenseKey: licenseKey,
        fingerprint: fingerprint
    )
}
```

`scheme` is `.ed25519Sign` (also the default for a license with no scheme set),
`.rsa2048Pkcs1Sign`, `.rsa2048Pkcs1PssSign` or `.ecdsaP256Sign`. `.rsa2048JwtRs256` throws
`TamgaCheckoutError.schemeNotSupported` — machine files are never JWT-signed.

Pass the public key exactly as the API gives it to you. Ed25519 is 32 raw bytes; ECDSA P-256 is
the 65-byte uncompressed point the account resource publishes (X.509 `SubjectPublicKeyInfo` is
also accepted); RSA is DER, either PKCS#1 `RSAPublicKey` or `SubjectPublicKeyInfo`.

Machine files are format v2, exactly as license files are: `alg` must end `+v2`, the signed
payload carries `meta` claims, and `exp` is enforced with the same 60-second tolerance. A file
whose checkout carried no `ttl` has no `exp` and genuinely never expires.

> **`fingerprint` binds an *encrypted* machine file, not a plain one.** It is HKDF `info`, so an
> encrypted file issued for another machine fails to decrypt. A plain machine file is signed but
> not encrypted, so the argument is unused on that path and the file is portable between machines
> as far as this SDK is concerned. If you accept plain machine files, compare the returned
> `machine.fingerprint` against your own — the SDK gives you the value but does not enforce the
> match. This matches the rest of the Tamga SDK fleet.

To supply a trusted timestamp instead of the local clock, or to read `iat`/`jti`/`kid` back, use
`verifyWithClaims(scheme:publicKey:licenseKey:fingerprint:now:)`:

```swift
let (machine, claims) = try MachineFile.parse(pem).verifyWithClaims(
    scheme: scheme,
    publicKey: publicKey,
    licenseKey: licenseKey,
    fingerprint: fingerprint,
    now: trustedUnixSeconds
)
```

### Key rotation

A file signed before the account rotated its signing key does not verify against the current key.
Pass a **key set** instead of a single key and it does — and, just as importantly, a file signed by
a key you do not have stops being indistinguishable from a forged one:

```swift
import Foundation
import Tamga

func verify(pem: String, licenseKey: String, keys: [TamgaSigningKey], serverNow: Int64) throws {
    do {
        let result = try LicenseFile.parse(pem).verifyWithClaims(
            signingKeys: keys,
            licenseKey: licenseKey,
            now: serverNow
        )
        if result.key.isRetired {
            // Authentic, but issued before the last rotation. Time for a fresh checkout.
        }
    } catch let error as TamgaSigningKeyError {
        // `.unknownSigningKey(kid:available:)` — the file names a key this set does not
        // hold. Refresh the key set; do NOT treat this as tampering.
        print(error.localizedDescription)
    } catch TamgaCheckoutError.signatureVerificationFailed {
        // The key it names IS in the set, and the signature still fails.
        // This one really is forged or corrupted.
    }
}
```

A `kid` is the first **eight bytes** of `SHA-256` over the public key **string** — the base64 text
the API publishes, not the decoded bytes — hex-encoded, so sixteen characters.
`TamgaSigningKey.keyId(forPublicKey:)` computes it, and
`TamgaSigningKey.ed25519(publicKey:)` builds a whole key record from a public key alone.

**Where the key set comes from is up to you, and pinning is usually the right answer.**
`TamgaClient.listSigningKeys()` fetches it, but that route needs the `account.read` permission and
a license-key credential does not hold it — an embedded client gets `403`. Build the set from keys
pinned into the app instead; an offline verifier that only works while it has a network is not
offline. An empty result from the endpoint is also normal rather than a fault: the key table is
written only by a rotation, so an account that has never rotated has no rows at all.

**Machine files: Ed25519 only.** The server computes a machine file's `kid` from the account's
Ed25519 key whatever scheme actually signed the file, so for an RSA- or ECDSA-signed machine file
the claim names a key that had no part in the signature. Those throw
`TamgaSigningKeyError.keyIdNotApplicable`; verify them with the scheme-and-key form above. Nothing
is lost — rotation only ever rotates the Ed25519 key. License files are always Ed25519-signed and
are unaffected.

### Offline proofs

An offline proof is a `meta.proof` string of the form `v1x0.<base64 signature>`, signed over a
canonical JSON payload built from the account, machine and your own dataset:

```swift
import Foundation
import Tamga

func verifyProof(
    _ proof: String,
    publicKeyDER: Data,
    accountId: String,
    machineId: String,
    fingerprint: String
) throws -> Bool {
    try MachineProof.parse(proof).verify(
        publicKeyDER: publicKeyDER,
        accountId: accountId,
        machineId: machineId,
        fingerprint: fingerprint,
        dataset: .object(["seats": .int(3)])
    )
}
```

The `dataset` you pass must be byte-identical in content to the one the proof was generated for;
an altered dataset fails verification.

## Security notes

Every claim here names the code that implements it.

- **Both file types derive their AES-256 key with HKDF-SHA256 (RFC 5869).** License files use
  `salt = "tamga:license-file-key-v1"`, `ikm = <license key>`, `info = "license-file"`
  (`Sources/Tamga/Crypto/Hkdf.swift::deriveLicenseFileKey`); machine files use
  `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`, `info = <fingerprint>`
  (`Sources/Tamga/Crypto/Hkdf.swift::deriveMachineFileKey`). The two are never interchangeable.
  The pre-v2 license-file transform — the license key's raw bytes zero-padded to 32 — was removed
  outright rather than deprecated, so no caller can opt back into it.
- **`exp` is enforced with a 60-second clock-skew tolerance**
  (`Sources/Tamga/Checkout/LicenseFile.swift::verifyWithClaims`). The tolerance is small on
  purpose: the local clock belongs to the attacker.
- **The license-file signature covers the base64 *string* bytes of `enc`, not the decoded
  payload** (`Sources/Tamga/Checkout/LicenseFile.swift::verify`).
- **Machine-file verifier dispatch uses the caller-supplied scheme, never the file's own `alg`**
  (`Sources/Tamga/Checkout/MachineFile.swift::verify`) — two distinct RSA schemes share one `alg`
  suffix on the wire, so trusting it would be an algorithm-confusion hole. `alg` is parsed and
  cross-checked against that scheme, never substring-matched
  (`Sources/Tamga/Checkout/MachineFileAlgorithm.swift`): it sits outside the signature, so on an
  otherwise valid file every byte of it is attacker-chosen.
- **Both file types' `exp` claims share one tolerance constant**
  (`Sources/Tamga/Checkout/LicenseFile.swift::clockSkewToleranceSeconds`), so they cannot drift
  into different grace periods.
- **The machine-file verifier is tested against files the server itself issued**
  (`Tests/TamgaTests/Fixtures/MachineFiles/`, driven by `manifest.json`) — not against
  certificates this repo encoded, which is how a shared misreading of the wire format stayed
  invisible to CI across the whole SDK fleet.
- **ECDSA keys are pinned to P-256 in both accepted encodings**
  (`Sources/Tamga/Crypto/Ecdsa.swift::importPublicKey`). A key on another curve is refused because
  its coordinates are not on P-256, whichever encoding it arrives in. An SPKI is additionally
  checked against the P-256 curve OID (via `Sources/Tamga/Crypto/DER.swift::ecNamedCurveOID`),
  because CryptoKit's SPKI parser does not validate the declared curve — that catches a key whose
  label contradicts its coordinates. See [SECURITY.md](SECURITY.md) for which of the two does what.
- **Everything fails closed**: AEAD tag mismatch throws instead of returning plaintext
  (`Sources/Tamga/Crypto/AesGcm.swift::open`), and a malformed PEM envelope throws the documented
  format error instead of trapping (`Sources/Tamga/Checkout/PemEnvelope.swift::strip`).
- **Offline proofs are always RSA-2048 PKCS#1 v1.5 / SHA-256** over recursively key-sorted
  canonical JSON (`Sources/Tamga/Proof.swift::verify`,
  `Sources/Tamga/CanonicalJson.swift::serialize`), independent of the license's scheme.

Full policy, including how to report a vulnerability: [SECURITY.md](SECURITY.md).

## Known gaps

This SDK is a protocol client, not a licensing-enforcement framework. The following are
deliberate boundaries, not oversights.

**Left to your application**

- **Machine fingerprints.** No SDK in the fleet *generates* one — choosing what identifies a
  machine is a product decision, not a library one (a cloned VM template shares its hardware ids, a
  container has none, a replaced motherboard changes them). Producing stable, device-specific
  components is still yours. Turning them into one canonical string is not: see
  [Fingerprint canonicalisation](#fingerprint-canonicalisation).
- **Embedding the account public key.** Rotation and key-id handling are no longer yours: pass a
  `[TamgaSigningKey]` to the offline verifiers and they select the key the file names. See
  [Key rotation](#key-rotation).
- **Persistence.** Nothing is written to disk. Storing `.lic`/`.machine` files, deciding when to
  refresh them, and securing the license key in the keychain are yours. The only cache is the
  60-second in-memory entitlement cache, which does not survive a restart.
- **Grace periods and offline policy**, and **enforcement**: a `ValidationCode` says what happened,
  not what your app should do about it.
- **Deciding what to do with a machine whose activation could not be validated.** If
  `activateMachine` creates the machine and then the validation call fails, the machine is handed
  back on `TamgaError.activationValidationFailed` rather than deleted — a network blip is not a
  verdict about the license. Retry the validation, or delete it with `deleteMachine(_:)`.
- **Clock trust.** A user who moves the clock backwards can revive an expired file. Offline
  verification accepts an explicit `now`, so you can pass a server-supplied timestamp.

**Server-side behaviour this SDK inherits**

- **License-key auth is off by default.** `AuthTransport.licenseKey` authenticates only when the
  license's policy sets `authentication_strategy` to `LICENSE` or `MIXED`. The column defaults to
  `TOKEN`, and `NONE` behaves the same way at that gate, so against a default policy every call
  fails `401 LICENSE_NOT_ALLOWED`. That is a policy configuration precondition — retrying it, or
  asking the user for a different key, accomplishes nothing.
- **Session-cookie auth needs an `Origin`, and the failure mode hides that.** The server does not
  reject a cookie whose `Origin` does not match its configured portal origin — it *ignores* the
  cookie and treats the request as anonymous, so the `401` you get back says no credentials were
  provided. `TamgaClient` now sends the header for `AuthTransport.sessionCookie` and for no other
  transport, defaulting to `TamgaClient.defaultPortalOrigin`; pass `origin:` if your server sets a
  different one, and match it exactly. One consequence rides along: any request carrying an
  `Origin` makes `quickValidate` skip its `last_validated_at` write, so under cookie auth that
  write does not happen.
- **8 of the 24 `ValidationCode` values are unreachable.** All 24 are modelled;
  `ValidationCode.isReachable` reports which. Do not build behaviour on an unreachable one.
- **Six of the eight `Scope` fields are enforced** — product, policy, user, environment,
  fingerprint and entitlements. `version` and `checksum` are not sent at all: present on the
  request they make the server reject the whole validate call with `422 SCOPE_NOT_SUPPORTED`.
- **`scope.entitlements` takes entitlement codes**, compared case-insensitively, satisfied by
  policy-inherited entitlements as well as directly attached ones.
- **Machine `memory` and `disk` are megabytes, not bytes.** Reporting bytes inflates the license's
  running total by 1,048,576× and trips `MEMORY_LIMIT_EXCEEDED` on the next activation.
- **Policy limits are checked twice**, at machine creation and again at validation, and the
  policy's overage strategy decides which one refuses. `activateMachine` handles both: a
  create-time `422` throws `machineOverLimit` with nothing to roll back, and an overage-path
  rejection deletes the row it created.
- **The heartbeat window is `policy.heartbeat_duration`, and 600s is only the fallback** the
  server applies when the policy leaves that field null. `HeartbeatScheduler.window` and the
  `defaultInterval` derived from it are both computed against the 600s fallback, so on a policy
  with a shorter window that default ping rate is too slow and machines will report `.dead`. Use
  `HeartbeatScheduler.sizedToPolicy(client:machineId:licenseId:)`, which reads the window off the
  licence's policy and sizes the interval from it — one extra request at startup. It reads the
  policy once and does not track later changes to it.
- **Every ping interval is floored at one second**, on both schedulers and however you reach them.
  `0.5` becomes `1`, and so do `0`, a negative and `.nan`; nothing throws, and an interval a real
  caller would pass is untouched. That is a bound on the request rate, not a rounding convenience:
  `Task.sleep` honours a sub-second delay *exactly* (measured on Swift 6.3: `0.001` sleeps a mean
  1.5 ms, about 665 pings a second), so a guard on only the non-positive case bounds nothing. To
  ask for the default, omit the parameter — passing `0` now means one second, not 200.

  The floor costs nothing a policy can express. `heartbeat_duration` is an integer-**seconds**
  column, and the server judges liveness on *truncated* whole seconds — `heartbeat_status_within`
  compares `(now - last_heartbeat_at).num_seconds() <= window_secs`, and `num_seconds()` truncates
  — so a machine first reads `.dead` at an age of `window_secs + 1`. Every window carries one free
  second, and a 1s window pinged every 1s has two seconds of slack, not zero. What does degrade is
  the divisor's promise of two tolerable consecutive losses: window 3 is where floor and divisor
  first agree, 2 keeps one spare ping, 1 keeps none. The window no interval can hold is `0`, not
  `1` — its whole grace *is* that free second. `interval(forWindowSeconds:)` therefore substitutes
  the 600s fallback *window* for a non-positive one before dividing, rather than dividing the raw
  value and letting the floor catch it: the verdict is `.dead` either way, so the schedule that
  reaches it with 200× fewer requests wins. A ~333 ms ping would in fact hold a `0` window, and is
  deliberately not used — it would tie this SDK's request rate to a server implementation artifact.
  A negative window is unserveable at any rate. The whole interaction is pinned as a table in
  `HeartbeatFloorTests`.
- **`Machine.nextHeartbeatAt` cannot be used to discover the window.** What it is computed against
  depends on which call produced the machine: `createMachine`, `activateMachine`, `pingHeartbeat`,
  `resetHeartbeat` and `updateMachine` return the written row without the policy joined, so it is
  `lastHeartbeatAt + 600s` whatever the policy says, while `getMachine`, `listMachines`,
  `checkOutMachine` and `generateOfflineProof` derive it from the policy. Two responses for the
  same machine seconds apart can disagree, and nothing on the wire says which you are holding.
- **`.dead` never comes back from a ping** — but it is ordinary elsewhere. `pingHeartbeat` writes
  `last_heartbeat_at = NOW()` and then derives the status from that same timestamp, so it answers
  `.alive` or `.resurrected`; `createMachine` and `resetHeartbeat` answer `.notStarted`; and
  `validate` never emits `heartbeatDead`. A `.dead` branch in a tick callback is unreachable code.
  `getMachine`, `listMachines`, `checkOutMachine`, `generateOfflineProof` — and `updateMachine`,
  a write that never touches the heartbeat column — can all report it. The rule that survives new
  routes is *what the response was built from*: a status derived from a timestamp the same request
  just wrote can never be `.dead`.
- **`.dead` would not mean the machine is gone either.** It means only that the last ping is older
  than the window. Culling is gated on the policy's `requireHeartbeat`, which is off by default, so
  on a default policy the row and its seat stay put however long a machine reads `.dead`, and the
  next ping revives it. So the rule is positive: the loop stops on no status at all —
  `HeartbeatScheduler` does not, deliberately. The one terminal signal a ping can give is a `404`
  (`TamgaError.isNotFound`), and that is what should trigger re-activation.
- **`resetHeartbeat` and `generateOfflineProof` always return `403` to a license-key credential.**
  Both are role-gated server-side; neither is available to an embedded client.
- **`quickValidate` writes `last_validated_at`** on every call — except when the request carries an
  `Origin` header, in which case it silently does not, with an identical response either way. For a
  genuinely side-effect-free check use `validateById` with `ValidateOptions(skipTouch: true)`.
- **`listEntitlements` is not paginable.** `page[after]` is ignored on that route, so `nextCursor`
  is always `nil` and a license with more than 100 effective entitlements cannot be enumerated in
  full. `hasEntitlement` reads that single page, so a `false` is authoritative only below the
  ceiling. Component listing is unaffected — keyset pagination works there.
- **The auto-update check's "no update" answer does not mean "you are up to date".**
  `checkForUpgrade` returns `.noneAvailable` for two server-side situations the server refuses to
  distinguish: there is no newer release, *or* there is one and this licence is not entitled to it.
  Both answer `204`, deliberately, so a denial cannot leak "a newer version exists but you cannot
  have it". Render it as "no update available" and hang renewal prompts off the licence's own
  expiry instead. A *suspended* licence is told, though — that one is a `403`.
- **`getPolicy` is unreachable with a licence key; `getLicensePolicy` is the same resource through
  a permission a licence token actually holds.** `GET /policies/{id}` asks for `policy.read`,
  which is not in the licence-token permission set, so it `403`s. `GET /licenses/{id}/policy` asks
  for `license.read`, which is. Both are exposed and each one's docs point at the other.
- **`getLicense`, `getLicensePolicy`, `updateMachine` and `deleteMachine` are not scoped to your
  own licence.** No machine or licence read/write route applies a licence-scope check, and a
  licence token's default permissions include `license.read`, `machine.read`, `machine.update` and
  `machine.delete`. So a licence key can read any licence in the account — **including its
  cleartext `key`** — and update or delete any machine in it. That is server-side and this SDK
  cannot fix it; it is documented here rather than papered over. Reported upstream.
- **`listMachines` has no fingerprint filter.** Its only near-equivalent is `query`
  (`filter[q]`), a `%term%` substring match spanning `name`, `hostname` and `fingerprint` — so
  compare `Machine.fingerprint` yourself on the results. `reactivateMachine` does exactly that.
- **`reactivateMachine` resolves a `409 FINGERPRINT_TAKEN` only within your own licence.** All
  three machine-uniqueness strategies include the caller's own rows, so a genuine re-activation is
  always found. A conflict raised by the wider scopes — the same fingerprint on a *different*
  licence — is rethrown unchanged rather than resolved, because that is the seat-sharing those
  scopes exist to refuse, and a machine resource carries no `license_id` for you to notice it with.
- **`health()` is the one call that goes out anonymously, deliberately.** The server resolves a
  request's credential *before* checking whether the route is public, so an unusable credential
  rejects `/v1/health` too — and in the server's default singleplayer mode a licence key under a
  default policy is unusable (`401 LICENSE_NOT_ALLOWED`). A probe that fails whenever your
  credential is the thing under suspicion answers nothing, so this one sends none. Every other
  route carries the credential you configured.
- **Nothing on the server ever deletes a process row.** The reaper meant to cull processes past
  their 30-second window does not run, so a registration this SDK creates and never deletes is
  permanent — and processes count against `policy.max_processes`. Call `deleteProcess`, or
  `ProcessHeartbeatScheduler.stopAndDelete()`, on the way out.
- **No RFC 9421 response-signature verification here.**
- **Artifact writes are absent.** `artifact.create`/`update`/`delete` are not in a licence token's
  permission set — publishing a build is an operator action. Reading and downloading artifacts
  *are* wrapped; see [Release artifacts](#release-artifacts).

**Transport hardening**

- **Redirects are refused.** The API never legitimately redirects on a route this SDK calls, and a
  3xx can carry credentials to a host you never configured — the session-cookie form especially,
  which no framework-level stripping protects. The one route that *does* redirect by default is
  the artifact download, and `downloadArtifact` asks it not to; see
  [Release artifacts](#release-artifacts).
- **Response bodies are capped at 32 MiB, enforced during the transfer.** A response that declares
  more than the cap is refused before any body arrives, and one that declares nothing is cut off the
  moment the running total crosses it. A timeout bounds how long a response may take, not how large
  it may be.
- **Requests carry a resource timeout, not just a per-request one.** `timeoutIntervalForRequest`
  resets on every chunk received, so a server trickling bytes can hold a connection open
  indefinitely under it alone.
- **Cancelling the calling task cancels the request**, rather than abandoning the `await` while the
  transfer continues in the background.

**Packaging**

- **A machine's `group` and `owner` sub-resources are not wrapped.**
  `GET`/`PATCH /machines/{id}/{group,owner}` return `groups` and `users` resources — two domains
  this SDK models nowhere else, and reassigning a machine's owner or group is an admin-console
  concern rather than an embedded-client one. Deliberate, and matching `tamga-python`'s call.
- **`TamgaObjC` exports no public interface yet.** The target builds and can be linked on Apple
  platforms, but the Objective-C wrapper over the Swift API is not written. It is excluded from
  Linux builds, where Objective-C interop does not exist.
- **Pre-v2 machine files are rejected, as pre-v2 license files already were.** A `.machine`
  whose `alg` lacks `+v2`, or whose payload carries no `meta` claims, no longer verifies. Both
  are genuine breaks for anyone holding an old file — re-issue it. The old behaviour accepted a
  v1 file and never enforced its expiry.

## Documentation

- [tamga.sh](https://tamga.sh) — product documentation and the SDK protocol reference.
- [`SECURITY.md`](SECURITY.md) — the verification contract, format v2, and vulnerability reporting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build, test and release workflow.
- [`CLAUDE.md`](CLAUDE.md) — architecture, dev commands, and gotchas for contributors.

## License

MIT — see [LICENSE](LICENSE).
