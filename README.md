# Tamga

Official Swift SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Swift applications.

> **What ships today.** Offline verification is implemented and tested: `.lic`/`.machine` file
> parse, verify and decrypt, offline proof verification, and the crypto primitives underneath
> them (118 tests, 80% line coverage gated in CI). The networked half of the SDK —
> `TamgaClient`, `Transport`, the JSON:API error model — is not implemented yet. Read
> [Known gaps](#known-gaps) before adopting.

## Install

Swift Package Manager, by git URL — SPM resolves packages by URL, and Tamga publishes no
central-registry package name:

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/tamga-sh/tamga-swift", from: "1.1.0"),
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

- **No HTTP client yet.** `TamgaClient`, `Transport`, `TamgaError`, `ValidationCode` and `Policy`
  are empty placeholders — see each file's own doc comment. Network calls (validation, check-in,
  checkout, machine management, entitlements) are your code's responsibility today; this SDK
  verifies what those calls return.
- **No 429 handling here yet, and that is a gap, not a server-side absence.** The server does
  return HTTP 429. The Tamga SDKs that ship a transport parse and cap `Retry-After`, retry with
  jittered exponential backoff, and scope auto-retry to `GET` plus five safe `POST` actions
  (`validate`, `validate-key`, `check-in`, `check-out`, `ping`) — creates are deliberately
  excluded. This SDK gets the same behaviour when its transport lands.
- **`TamgaObjC` exports no public interface yet.** The target builds and can be linked, but the
  Objective-C wrapper over the Swift API is not written.
- **Machine files carry no signed claims.** Only license files have `meta` claims and the `+v2`
  `alg` check; a machine file's binding to one machine comes from the fingerprint being HKDF
  `info`.

## Documentation

- [tamga.sh](https://tamga.sh) — product documentation and the SDK protocol reference.
- [`SECURITY.md`](SECURITY.md) — the verification contract, format v2, and vulnerability reporting.
- [`CLAUDE.md`](CLAUDE.md) — architecture, dev commands, and gotchas for contributors.

## License

MIT — see [LICENSE](LICENSE).
