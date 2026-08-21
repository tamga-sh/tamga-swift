# Tamga

Official Swift SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Swift applications.

Two independent surfaces, either usable without the other:

- **`TamgaClient`** talks to the API — validation, activation, checkout, heartbeats, components,
  processes and entitlements. Twenty `async` endpoints, seven auth transports, and automatic
  handling of HTTP 429.
- **`LicenseFile`, `MachineFile` and `MachineProof`** verify `.lic`/`.machine` files and offline
  proofs with **no network access at all**, once your account's public key is embedded in the app.

Runs on macOS 13+, iOS 16+ and Linux. 223 tests, with an 80% line-coverage gate in CI.

## Install

Swift Package Manager, by git URL — SPM resolves packages by URL, and Tamga publishes no
central-registry package name:

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/tamga-sh/tamga-swift", from: "1.2.0"),
]
```

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
`TamgaCheckoutError.schemeNotSupported` — machine files are never JWT-signed. RSA and ECDSA keys
are X.509 `SubjectPublicKeyInfo` DER; Ed25519 keys are raw 32 bytes.

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
  suffix on the wire, so trusting it would be an algorithm-confusion hole.
- **ECDSA keys are checked for the P-256 curve OID before use**
  (`Sources/Tamga/Crypto/Ecdsa.swift::verify`, via `Sources/Tamga/Crypto/DER.swift::ecNamedCurveOID`).
  CryptoKit's SPKI parser validates coordinate length but not the declared curve.
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

- **Machine fingerprints.** No SDK in the fleet generates one. Producing a stable, device-specific,
  reasonably tamper-resistant fingerprint — and keeping it stable across reinstalls — is yours.
- **Embedding the account public key**, plus rotation and key-id handling.
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
- **The heartbeat window is a hardcoded 600s**, not driven by `policy.heartbeat_duration`.
- **`resetHeartbeat` and `generateOfflineProof` always return `403` to a license-key credential.**
  Both are role-gated server-side; neither is available to an embedded client.
- **`quickValidate` writes `last_validated_at`** on every call — except when the request carries an
  `Origin` header, in which case it silently does not, with an identical response either way. For a
  genuinely side-effect-free check use `validateById` with `ValidateOptions(skipTouch: true)`.
- **`listEntitlements` is not paginable.** `page[after]` is ignored on that route, so `nextCursor`
  is always `nil` and a license with more than 100 effective entitlements cannot be enumerated in
  full. `hasEntitlement` reads that single page, so a `false` is authoritative only below the
  ceiling. Component listing is unaffected — keyset pagination works there.
- **No auto-update API and no RFC 9421 response-signature verification here.** The server's
  `GET /releases/actions/upgrade` does work (it is public, and answers `204` when you are already
  current); this SDK simply does not wrap it yet. Artifact download is a different story — the route
  exists but no role grants the permission it requires, so it `403`s for every client.

**Transport hardening**

- **Redirects are refused.** The API never legitimately redirects, and a 3xx can carry credentials
  to a host you never configured — the session-cookie form especially, which no framework-level
  stripping protects.
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

- **`TamgaObjC` exports no public interface yet.** The target builds and can be linked on Apple
  platforms, but the Objective-C wrapper over the Swift API is not written. It is excluded from
  Linux builds, where Objective-C interop does not exist.
- **Machine files carry no signed claims.** Only license files have `meta` claims and the `+v2`
  `alg` check; a machine file's binding to one machine comes from the fingerprint being HKDF
  `info`.

## Documentation

- [tamga.sh](https://tamga.sh) — product documentation and the SDK protocol reference.
- [`SECURITY.md`](SECURITY.md) — the verification contract, format v2, and vulnerability reporting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build, test and release workflow.
- [`CLAUDE.md`](CLAUDE.md) — architecture, dev commands, and gotchas for contributors.

## License

MIT — see [LICENSE](LICENSE).
