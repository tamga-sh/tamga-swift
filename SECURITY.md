# Security Policy

## Scope

`tamga-swift` binds to `tamga-c`'s stable C ABI rather than reimplementing crypto natively. Only four operations cross the FFI boundary — see `CLAUDE.md`'s "Crypto-Boundary Rule". The highest-risk code lives in:

- [`Sources/Tamga/FFI/`](Sources/Tamga/FFI/) — the `CTamgaShim` wrapper layer; the only files allowed to import the C shim.
- [`Sources/Tamga/Checkout/`](Sources/Tamga/Checkout/) — `.lic`/`.machine` file parse/verify/decrypt.
- [`Sources/Tamga/Proof.swift`](Sources/Tamga/Proof.swift) — offline proof.

Note: as of this writing, `tamga-swift` is pre-release scaffolding blocked on `tamga-c`'s ABI freeze — no FFI wiring or business logic exists yet, so most reports will not apply until real implementation lands.

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
  transform, not a real KDF. This is mandated by server wire compatibility.
- Auth is not currently enforced server-side on the license/machine
  validate/check-in endpoints (a server-side gap, not a client-side one) —
  this SDK still always sends its configured credentials for
  forward-compatibility.
- No client-side rate-limit/backoff handling — the server does not send
  `429` today.
