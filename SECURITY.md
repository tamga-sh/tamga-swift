# Security Policy

## Scope

`tamga-swift` implements Tamga's offline verification cryptography natively in Swift, using Apple's CryptoKit and Security frameworks exclusively — no third-party crypto dependency, no C FFI. See `CLAUDE.md`'s "Crypto Architecture" section for the full rationale and primitive-by-primitive mapping. The highest-risk code lives in:

- [`Sources/Tamga/Crypto/`](Sources/Tamga/Crypto/) — Ed25519, AES-256-GCM, HKDF-SHA256, ECDSA-P256, and RSA (PKCS#1v1.5/PSS) verification primitives.
- [`Sources/Tamga/Checkout/`](Sources/Tamga/Checkout/) — `.lic`/`.machine` file parse/verify/decrypt.
- [`Sources/Tamga/Proof.swift`](Sources/Tamga/Proof.swift) — offline proof verification.
- [`Sources/Tamga/CanonicalJson.swift`](Sources/Tamga/CanonicalJson.swift) — the canonical JSON serializer the offline-proof signature covers.

Out of scope for now: this SDK ships no HTTP client. `TamgaClient`, `Transport` and the JSON:API
error model are empty placeholders, so nothing here talks to the network — the attack surface is
entirely "files and strings the caller already holds".

## Offline license file format v2 (compatibility warning)

As of 1.1.0 a `.lic` file must be format v2: its `alg` is exactly `base64+ed25519+v2` or
`aes-256-gcm+ed25519+v2`, and its payload carries signed `meta` claims (`iat`, `exp`, `jti`,
`kid`). **v1 files are rejected outright — there is no fallback path.** If you hold `.lic` files
issued before v2, re-issue them; this SDK will refuse them
(`Sources/Tamga/Checkout/LicenseFile.swift::verify(publicKey:)` rejects a v1 `alg`, and
`verifyWithClaims(publicKey:licenseKey:now:)` rejects a payload with no `meta` claims).

That break is the point of v2. In v1 the requested `ttl`/`expiry` lived only in the JSON:API
envelope around the certificate, never inside the signed bytes — so a 24-hour trial file was
cryptographically valid forever, because whoever holds the file can simply drop the envelope.

## Supported Versions

The current release series is 1.x (latest tag: `v1.1.0`). The two most recent minor versions
receive security patches; older ones do not.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security vulnerability.**

Report it privately via GitHub's [private vulnerability reporting](https://github.com/tamga-sh/tamga-swift/security/advisories/new)
feature on this repository. Include:

- The affected file(s)/function(s) and, if possible, a minimal reproduction.
- Whether the issue is a verification bypass (a forged `.lic`/`.machine` file
  or offline proof that this SDK would incorrectly accept as valid), an
  information leak, a denial-of-service via malformed/adversarial input, or
  something else.
- The version (git commit or tagged release) you tested against.

You should receive an initial response within 5 business days. Confirmed
vulnerabilities will be fixed in a private branch and disclosed via a GitHub
Security Advisory alongside the patched release; we will credit reporters
who wish to be credited.

## What Counts as a Vulnerability Here

Given this SDK's actual attack surface (an offline file/proof verifier, not
a server), the highest-severity class of bug is **a verifier that accepts
something it should reject** — for example, a signature check computed over
the wrong bytes, a scheme dispatch that picks the wrong algorithm, or an
offline proof that verifies against a differently-serialized (but
semantically equivalent) payload.

## What the Verifier Actually Does

Each claim below names the code that implements it.

- **Both offline file types derive their AES-256 key with HKDF-SHA256 (RFC 5869).** A license
  file uses `salt = "tamga:license-file-key-v1"`, `ikm = <license key>`, `info = "license-file"`
  (`Sources/Tamga/Crypto/Hkdf.swift::deriveLicenseFileKey`). A machine file uses
  `salt = "tamga:machine-file-key-v1"`, `ikm = <license key>`, `info = <machine fingerprint>`
  (`Sources/Tamga/Crypto/Hkdf.swift::deriveMachineFileKey`). The two derivations use different
  salts and are never interchangeable, and a machine file therefore cannot be opened anywhere but
  on the machine it was issued for.
- **`exp` is enforced, with a 60-second clock-skew tolerance.**
  `Sources/Tamga/Checkout/LicenseFile.swift::verifyWithClaims(publicKey:licenseKey:now:)`, whose
  tolerance constant is `LicenseFile.clockSkewToleranceSeconds`. The tolerance is deliberately
  small: the local clock belongs to the attacker, so a generous allowance is a free extension on
  every expired file. `verifyWithClaims` takes `now` from the caller so an app that keeps a
  server-supplied timestamp can pass that instead of trusting the system clock.
- **The license-file signature covers the base64 *string* bytes of `enc`, not the decoded
  payload** (`Sources/Tamga/Checkout/LicenseFile.swift::verify(publicKey:)`). Getting that byte
  source wrong is the most consequential trap in the wire format.
- **Machine-file signature dispatch keys off the caller-supplied `LicenseScheme`, never the
  file's own `alg` string** (`Sources/Tamga/Checkout/MachineFile.swift::verify(scheme:publicKey:)`).
  `RSA_2048_PKCS1_SIGN` and `RSA_2048_JWT_RS256` both serialize to the same `"rsa-sha256"` suffix,
  so trusting the self-declared string would be an algorithm-confusion hole. `RSA_2048_JWT_RS256`
  throws rather than verifying anything.
- **ECDSA public keys are checked for the P-256 curve OID before use**
  (`Sources/Tamga/Crypto/Ecdsa.swift::verify`, backed by
  `Sources/Tamga/Crypto/DER.swift::ecNamedCurveOID`). CryptoKit's own SPKI parser validates
  coordinate length but not the declared curve, so without this guard a signature made on a
  different same-size curve would verify.
- **Decryption fails closed.** AES-GCM tag mismatch throws rather than returning plaintext
  (`Sources/Tamga/Crypto/AesGcm.swift::open`), and a truncated or overlapping PEM envelope throws
  the documented format error rather than trapping
  (`Sources/Tamga/Checkout/PemEnvelope.swift::strip`).
- **Offline proofs are always RSA-2048 PKCS#1 v1.5 / SHA-256 over a recursively key-sorted
  canonical JSON payload** (`Sources/Tamga/Proof.swift::verify`,
  `Sources/Tamga/Proof.swift::buildSignedPayload`, `Sources/Tamga/CanonicalJson.swift::serialize`,
  `Sources/Tamga/Crypto/Rsa.swift::verifyPkcs1`) — never dispatched by the license's scheme.

## Known, Deliberate Non-Vulnerabilities

The following are intentional design decisions, not bugs, and reports about
them will be closed without action (though corrections/clarifications are
welcome):

- The certificate's `alg` field is read but not itself covered by the
  signature (only `enc` is signed) — it's used solely to choose
  AES-GCM-decrypt vs. plain-decode, never to select the signature verifier
  (that's always Ed25519 for license files, and always the caller-supplied
  scheme, never the file's own `alg`, for machine files). Flipping `alg` on
  an otherwise-validly-signed file fails closed in both directions
  (ciphertext misread as plaintext JSON fails to parse; plaintext misread as
  `nonce||ciphertext||tag` fails the AES-GCM tag check) — this is an
  accepted wire-format tradeoff shared with the other Tamga SDKs, not an
  oversight.
- `TamgaCheckoutError.decryptionFailed` is deliberately distinct from
  `.signatureVerificationFailed`, so a caller can say "check your license key" instead of "this
  file may be tampered with". Unlike a network-facing oracle there is no adversary benefit to
  collapsing the two for a file the user already holds.
- Machine files carry no `meta` claims and are not subject to the `+v2` `alg` check; their binding
  to a single machine comes from the fingerprint being HKDF `info`, which makes a wrong-machine
  file fail the AEAD tag check.
