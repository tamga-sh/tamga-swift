# Security Policy

## Scope

`tamga-swift` implements Tamga's offline verification cryptography natively in Swift, on
[apple/swift-crypto](https://github.com/apple/swift-crypto) — one code path across macOS, iOS and
Linux, and no C FFI. On Apple platforms `Crypto` forwards to CryptoKit, so this is a portable
spelling of the same primitives rather than a different backend there; `CryptoExtras` supplies RSA,
which neither exposes. The Security framework is no longer used at all — it was Apple-only and made
the package impossible to compile on Linux. swift-crypto is pinned to `4.5.1+`, and that floor is a
security fix, not housekeeping: the 3.x line corrupts the heap on
`_RSA.Signing.PublicKey(derRepresentation:)`'s malformed-DER error path, which is reachable from
production with attacker-supplied key bytes. See `CLAUDE.md`'s "Crypto Architecture" section for the
full rationale and primitive-by-primitive mapping. The highest-risk code lives in:

- [`Sources/Tamga/Crypto/`](Sources/Tamga/Crypto/) — Ed25519, AES-256-GCM, HKDF-SHA256, ECDSA-P256, and RSA (PKCS#1v1.5/PSS) verification primitives.
- [`Sources/Tamga/Checkout/`](Sources/Tamga/Checkout/) — `.lic`/`.machine` file parse/verify/decrypt.
- [`Sources/Tamga/Proof.swift`](Sources/Tamga/Proof.swift) — offline proof verification.
- [`Sources/Tamga/CanonicalJson.swift`](Sources/Tamga/CanonicalJson.swift) — the canonical JSON serializer the offline-proof signature covers.

The HTTP surface is **in** scope, and this section used to say the opposite. `TamgaClient`,
`Transport` and the JSON:API error model were empty placeholders when this policy was written;
they are now implemented and tested — 31 client methods, auth, 429 retry, `EntitlementCache`, the
heartbeat schedulers. Reports about `Transport`'s URL construction and path escaping, auth header
and query-parameter handling, retry behaviour, or response decoding are all in scope — not just
"files and strings the caller already holds".

Two properties of that surface are **server-side** and are documented rather than fixed here, so
please do not report them against this repository:

- `GET /licenses/{id}` and `GET /licenses/{id}/policy` apply no licence-scope confinement, and the
  licence resource carries `attributes.key` in cleartext. A licence token holding `license.read` —
  which is its default — can read any licence in the same account, key included.
- No machine route applies a licence-scope check either, and a licence token's defaults include
  `machine.read`, `machine.update` and `machine.delete`. So a licence key can update or delete any
  machine in the account.

Both are filed upstream. `getLicense(_:)`, `updateMachine(_:options:)` and `deleteMachine(_:)`
say so in their own doc comments; nothing in this SDK describes that surface as scoped.

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

The current release series is 1.x. The two most recent minor versions receive security patches;
older ones do not. The exact latest tag is on the
[releases page](https://github.com/tamga-sh/tamga-swift/releases) — naming it here has gone stale
once already.

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
  salts and are never interchangeable, so an **encrypted** machine file cannot be opened anywhere
  but on the machine it was issued for. That binding is cryptographic only for encrypted files: a
  *plain* machine file is signed but not encrypted, so the `fingerprint` argument is unused on that
  path and the file's binding lives in the `fingerprint` field of the signed payload. A caller who
  accepts plain machine files must compare `machine.fingerprint` against its own — the SDK returns
  the value but does not enforce the match, matching `tamga-go`'s `MachineFile.Verify`.
- **`exp` is enforced, with a 60-second clock-skew tolerance — for both file types.**
  `Sources/Tamga/Checkout/LicenseFile.swift::verifyWithClaims(publicKey:licenseKey:now:)` and
  `Sources/Tamga/Checkout/MachineFile.swift::verifyWithClaims(scheme:publicKey:licenseKey:fingerprint:now:)`,
  which share the single tolerance constant `LicenseFile.clockSkewToleranceSeconds` so the two
  paths cannot drift into different grace periods. The tolerance is deliberately
  small: the local clock belongs to the attacker, so a generous allowance is a free extension on
  every expired file. `verifyWithClaims` takes `now` from the caller so an app that keeps a
  server-supplied timestamp can pass that instead of trusting the system clock. A **missing** `exp`
  is legitimate on both file types — it means the checkout carried no `ttl` — and is not an error.
- **The signature covers the *string* bytes of `enc`, not the decoded payload**
  (`Sources/Tamga/Checkout/LicenseFile.swift::verify(publicKey:)`,
  `Sources/Tamga/Checkout/MachineFile.swift::verifyWithClaims(...)`). Getting that byte
  source wrong is the most consequential trap in the wire format. For an encrypted machine file
  `enc` is not base64 at all but `"<nonce_b64>.<cipher_b64>"`, and the signature still covers that
  whole string: verify first, then split, then decode each half, then decrypt. Nothing inside `enc`
  is parsed before the signature has passed.
- **Machine-file signature dispatch keys off the caller-supplied `LicenseScheme`, never the
  file's own `alg` string** (`Sources/Tamga/Checkout/MachineFile.swift::verify(scheme:publicKey:)`).
  `RSA_2048_PKCS1_SIGN` and `RSA_2048_JWT_RS256` both serialize to the same `"rsa-sha256"` suffix,
  so trusting the self-declared string would be an algorithm-confusion hole. `RSA_2048_JWT_RS256`
  throws rather than verifying anything.
- **ECDSA public keys are pinned to P-256 on both accepted encodings**
  (`Sources/Tamga/Crypto/Ecdsa.swift::importPublicKey`). Two encodings are accepted because the
  server publishes the bare point: an X.509 `SubjectPublicKeyInfo`, and the 65-byte uncompressed
  X9.63 point (`0x04 ‖ X ‖ Y`). They are pinned by different mechanisms, and neither is a fallback
  for the other:
  - **Point validity, on both paths.** A key on a genuinely different curve is rejected because its
    coordinates do not satisfy P-256's curve equation — BoringSSL's `EC_KEY_check_key`, reached from
    both initializers. Verified against a real secp256k1 key in BOTH encodings — its SPKI, and its
    generator as a bare 65-byte point — and against a P-256 point with one coordinate bit flipped;
    `EcdsaTests.swift` carries all three as regression tests. This,
    not the OID check below, is what makes a foreign-curve signature unverifiable here — helped by
    `Ecdsa.verify` being hardcoded to build a `P256.Signing.PublicKey`, so the curve the math runs
    on is fixed at compile time and cannot be chosen by the key.
  - **The curve OID, on the SPKI path.** CryptoKit's own SPKI parser does not validate the declared
    curve, so an SPKI is additionally checked against P-256 explicitly
    (`Sources/Tamga/Crypto/DER.swift::ecNamedCurveOID`). To be precise about what this catches: a
    *mislabelled* key — a real P-256 point wearing another curve's OID — which is a valid P-256 key
    that would verify correctly, and is refused because a key whose metadata contradicts itself
    should not be trusted. It is defence in depth against this type ever growing a dynamic
    multi-curve dispatch (the shape in which this bug class is genuinely live in the fleet's
    generic-`ECDsa` verifiers), not the boundary holding back a forgery today.
  - **Length dispatch cannot be steered** to route an SPKI into the bare-point branch: the shortest
    P-256 SPKI is ~91 bytes, so no 65-byte input can be one.
- **ECDSA verifies over `SHA-256(enc)`, and parses the signature as ASN.1 DER**
  (`Sources/Tamga/Crypto/Ecdsa.swift::verify`). The server signs with
  `ECDSA_P256_SHA256_ASN1_SIGNING`, so a 64-byte P1363 `(r, s)` blob is not the wire format and is
  not accepted. The `DataProtocol` overload of `isValidSignature` applies SHA-256 itself; a
  pre-hashed value is never handed to it, which would otherwise verify the wrong bytes silently.
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
  signature (only `enc` is signed). It never selects the signature verifier —
  that's always Ed25519 for license files, and always the caller-supplied
  scheme for machine files, because `RSA_2048_PKCS1_SIGN` and
  `RSA_2048_JWT_RS256` share the `rsa-sha256` suffix and so the string cannot
  name a scheme. `alg` chooses only AES-GCM-decrypt vs. plain-decode, and is
  otherwise a cross-check with a veto: a machine file whose declared signing
  suffix disagrees with the caller's scheme is refused
  (`MachineFile.validatedAlgorithm`), as is one whose `alg` is not a
  well-formed `<encoding>+<signing>+v2` string
  (`MachineFileAlgorithm.parse`). Because every byte of `alg` is
  attacker-chosen on a file that otherwise verifies, it is parsed strictly
  rather than substring-matched, and flipping it fails closed: a rejected
  `alg` never reaches a decoder at all, and a swapped *encoding* prefix is
  refused by the reader it names (a plain payload has no `.` for the
  dot-separated reader; a dot-separated one is not valid base64 for the plain
  reader, since `Data(base64Encoded:)` is strict and no call site passes
  `.ignoreUnknownCharacters`).
- `TamgaCheckoutError.decryptionFailed` is deliberately distinct from
  `.signatureVerificationFailed`, so a caller can say "check your license key" instead of "this
  file may be tampered with". Unlike a network-facing oracle there is no adversary benefit to
  collapsing the two for a file the user already holds.
- A plain (unencrypted) machine file is signed but not bound to one machine by the SDK. Its
  `fingerprint` argument is unused on that path, and the binding lives in the signed payload's own
  `fingerprint` field, which the caller compares. Only an *encrypted* machine file is bound
  cryptographically, through the fingerprint being HKDF `info`. This is deliberate and shared with
  the rest of the fleet (`tamga-go`'s `MachineFile.Verify` uses the fingerprint only for the
  encrypted branch too); see "What the Verifier Actually Does" above.

> **Corrected 2026-08-21.** This section previously claimed machine files "carry no `meta` claims
> and are not subject to the `+v2` `alg` check", and listed that under deliberate non-vulnerabilities.
> Both halves were false: `check_out_machine.rs` signs the same `LicenseFileClaims` struct the
> license path does, and `machine_file_alg_str` appends a mandatory `+v2`. The verifier did not read
> either, so a machine file with a one-hour TTL verified forever and a v1 downgrade was accepted —
> and this document told anyone who reported it that the behaviour was intended. Both are now
> enforced (`MachineFileAlgorithm`, `MachineFile.verifyWithClaims`). If you reported either issue
> against an earlier version and were waved off on the strength of this section, you were right and
> the document was wrong.
