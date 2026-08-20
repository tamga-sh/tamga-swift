# Contributing to tamga-swift

## Status

The SDK is complete: the HTTP client (`TamgaClient`, `Transport`, `AuthTransport`) and offline
verification (`LicenseFile`, `MachineFile`, `MachineProof`) are both implemented and tested.

## Requirements

A Swift 6.1 toolchain or newer. No other setup: `swift build` and `swift test` work on a fresh
checkout, with no sibling repo, binary target, or local override to apply.

The 6.1 floor comes from `apple/swift-crypto`'s transitive `swift-asn1` dependency. Xcode 16.4,
which CI pins, ships Swift 6.1.2.

## Commands

```bash
swift build                          # build all targets
swift test                           # run the suite (Swift Testing, NOT XCTest)
swiftlint lint --strict              # as CI runs it — warnings fail
swift test --enable-code-coverage    # then see the coverage gate below
```

Linux, as CI runs it:

```bash
docker run --rm -v "$PWD":/w -w /w swift:6.1-jammy swift test
```

The coverage gate:

```bash
swift test --enable-code-coverage
BIN_PATH="$(swift build --show-bin-path)"
XCTEST_BUNDLE=$(find "$BIN_PATH" -name '*.xctest' -maxdepth 1 | head -n1)
xcrun llvm-cov export -summary-only \
  "${XCTEST_BUNDLE}/Contents/MacOS/$(basename "${XCTEST_BUNDLE}" .xctest)" \
  -instr-profile "${BIN_PATH}/codecov/default.profdata" \
  -ignore-filename-regex='(\.build|Tests)/' \
  | ./Scripts/check-coverage.sh
```

`-ignore-filename-regex` is not optional. Without it the summary also covers swift-crypto and its
vendored BoringSSL, which this suite does not exercise, and the reported figure collapses.

## Expectations

- **Tests use Swift Testing** (`import Testing`, `@Test`/`@Suite`/`#expect`), never XCTest. This is
  a deliberate convention, not a stopgap.
- **Network-touching code sits behind `HTTPRequestPerforming`**, and tests inject `MockPerformer`.
  Do not reach for `URLProtocol` stubbing: it is unreliable on swift-corelibs-foundation and would
  make the suite Apple-only. Never hit a live network from a unit test.
- **Three CI jobs must pass**: macOS (lint + test + coverage), iOS (simulator), and Linux.
- **Changes under `Crypto/`, `Checkout/` or `Proof.swift` require security review.** `CODEOWNERS`
  routes them accordingly, and the PR template carries the checkbox. A HIGH-severity finding on a
  crypto path blocks merge.
- **Behavioural changes to the network surface** should also update
  `../docs/api-client-contract.md`, which is normative across the SDK fleet.

## Branches and commits

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/). `release-please`
parses them directly to drive `CHANGELOG.md` and cut tags — a commit that does not follow the
convention is invisible to the release automation, not merely a style nit. The git tag *is* the
release; there is no package registry to publish to.
