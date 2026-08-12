# Security Policy

## Scope

`tamga-swift` reimplements Tamga's offline verification cryptography natively in Swift, using Apple's CryptoKit and Security frameworks exclusively — no third-party crypto dependency, no C FFI. See `CLAUDE.md`'s "Crypto Architecture" section for the full rationale and primitive-by-primitive mapping. The highest-risk code lives in:

- [`Sources/Tamga/Crypto/`](Sources/Tamga/Crypto/) — Ed25519, AES-256-GCM, HKDF-SHA256, ECDSA-P256, and RSA (PKCS#1v1.5/PSS) verification primitives.
- [`Sources/Tamga/Checkout/`](Sources/Tamga/Checkout/) — `.lic`/`.machine` file parse/verify/decrypt.
- [`Sources/Tamga/Proof.swift`](Sources/Tamga/Proof.swift) — offline proof verification.
- [`Sources/Tamga/CanonicalJson.swift`](Sources/Tamga/CanonicalJson.swift) — the canonical JSON serializer the offline-proof signature covers.

Out of scope for now: the full `TamgaClient` HTTP-facing surface (entitlements, heartbeat scheduling, the JSON:API error envelope) is still deferred to a future session — see the scope notes in `Errors.swift`, `Models/License.swift`, `Models/Machine.swift`, and `Models/Policy.swift`.

## Supported Versions

This SDK is pre-1.0; the latest published minor version receives security
fixes. Once a 1.x series exists, the two most recent minor versions will
receive security patches.

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

## Known, Deliberate Non-Vulnerabilities

The following are intentional design decisions, not bugs, and reports about
them will be closed without action (though corrections/clarifications are
welcome):

- The `.lic` file's encryption key derivation is a zero-pad/truncate
  transform (`NaiveKey`), not a real KDF — mandated by server wire
  compatibility. The `.machine` file uses real HKDF-SHA256 (`Hkdf`) instead;
  the two are never interchangeable.
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
- Auth is not currently enforced server-side on the license/machine
  validate/check-in endpoints (a server-side gap, not a client-side one) —
  this SDK still always sends its configured credentials for
  forward-compatibility.
- No client-side rate-limit/backoff handling — the server does not send
  `429` today.
