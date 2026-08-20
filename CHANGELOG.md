# Changelog

## [1.2.0](https://github.com/tamga-sh/tamga-swift/compare/v1.1.2...v1.2.0) (2026-08-20)


### Features

* **client:** implement the HTTP API client, and support Linux ([#17](https://github.com/tamga-sh/tamga-swift/issues/17)) ([97659d0](https://github.com/tamga-sh/tamga-swift/commit/97659d076574ee426430de5b9637ce27c2f123b6))

## [1.1.2](https://github.com/tamga-sh/tamga-swift/compare/v1.1.1...v1.1.2) (2026-08-18)


### Bug Fixes

* **ci:** open release PRs with a GitHub App token so required checks run ([#13](https://github.com/tamga-sh/tamga-swift/issues/13)) ([4e0e6ab](https://github.com/tamga-sh/tamga-swift/commit/4e0e6ab7da7ee94b9e58ff01b68703be9d796905))

## [1.1.1](https://github.com/tamga-sh/tamga-swift/compare/v1.1.0...v1.1.1) (2026-08-18)


### Bug Fixes

* correct SDK documentation and align package metadata ([2a020be](https://github.com/tamga-sh/tamga-swift/commit/2a020be079999989598dd63f95c26a4ec39d4fc6))

## [1.1.0](https://github.com/tamga-sh/tamga-swift/compare/v1.0.0...v1.1.0) (2026-08-13)


### ⚠ BREAKING CHANGES

* offline license files must be format v2 (`alg` ending in `+v2`). v1 files are rejected outright with no compatibility path. `Crypto/NaiveKey.swift` is removed, not deprecated.

### Features

* license-file HKDF + offline format v2 ([6359058](https://github.com/tamga-sh/tamga-swift/commit/63590587e3cb300a4b05d94093675cde6430ae24))


### Miscellaneous Chores

* set explicit release version ([968e5cc](https://github.com/tamga-sh/tamga-swift/commit/968e5cc150b78eff0aa3ddcfcae0c08da427dda0))

## 1.0.0 (2026-08-12)


### Features

* **ci:** implement real XCFramework build + Package.swift bot-commit ([6ad2e1d](https://github.com/tamga-sh/tamga-swift/commit/6ad2e1d151ac538699e9cd5b1c51bfb5e9ad01d3))
* implement checkout composition (LicenseFile, MachineFile) ([830db03](https://github.com/tamga-sh/tamga-swift/commit/830db03831c17714a00b8368d4fcab764ff22982))
* implement native crypto primitives (Ed25519, AES-GCM, HKDF, ECDSA, RSA, NaiveKey) ([d13b8e8](https://github.com/tamga-sh/tamga-swift/commit/d13b8e877d4abc51a3d0cf43570aae556c358df4))
* implement offline proof + canonical JSON (MachineProof, CanonicalJson) ([02faecf](https://github.com/tamga-sh/tamga-swift/commit/02faecfa92a5d344281d6488c7dd2aa9b09b0e21))
* pivot from tamga-c FFI binding to native Swift crypto reimplementation ([c8c14bb](https://github.com/tamga-sh/tamga-swift/commit/c8c14bb554e66fd8807ba41de6e0af4ed3953944))
* scaffold project structure ([d97f0f7](https://github.com/tamga-sh/tamga-swift/commit/d97f0f766ac199fea205b5f21e825f64cb5db277))


### Bug Fixes

* add a placeholder source file to CTamgaShim for xcodebuild's build graph ([d021d63](https://github.com/tamga-sh/tamga-swift/commit/d021d6339d55a8704aa2acc776dfc7efaf13755c))
* address independent review findings before merge ([92426b2](https://github.com/tamga-sh/tamga-swift/commit/92426b2b50a0d6661980a31dda8eff9eff25803d))
* build a real XCFramework from tamga-c's releases in CI tests ([9001d52](https://github.com/tamga-sh/tamga-swift/commit/9001d528e9806f2109dd9e54217c2f1dbddbf5c9))
* build a real XCFramework from tamga-c's releases in CI tests ([e23753d](https://github.com/tamga-sh/tamga-swift/commit/e23753d79195723a904478d3277eb9fd5faf6983))
* create a fresh iOS Simulator device in CI instead of searching for one ([6aac9b3](https://github.com/tamga-sh/tamga-swift/commit/6aac9b3bbe5a5ecddaf63ad6ecbb9644c3734768))
* discover an available iOS Simulator device instead of hardcoding one ([f9b2ba9](https://github.com/tamga-sh/tamga-swift/commit/f9b2ba9c4e827a6d1ea71f4cf57a8e079894bf6d))
* explicitly download/install a matching iOS Simulator platform in CI ([4b3900f](https://github.com/tamga-sh/tamga-swift/commit/4b3900f3d98251ca0f0594303b4f6a57ef36792b))
* match the created iOS Simulator's runtime to Xcode's own SDK version ([6401634](https://github.com/tamga-sh/tamga-swift/commit/640163471738cef33ce4a5e8bda6740203b94ecd))
* move inline simulator-discovery Python into a proper script file ([014ef68](https://github.com/tamga-sh/tamga-swift/commit/014ef6890554082bd50f3451b61ee97c2ad4e442))
* pin CI to Xcode 16.4, whose default Simulator SDK is actually installed ([1552d23](https://github.com/tamga-sh/tamga-swift/commit/1552d23a65542d8daae9dbd3f5d625b5a9ba46b7))
* pin tamga-c reusable workflow call to a release tag, not [@main](https://github.com/main) ([4a84baa](https://github.com/tamga-sh/tamga-swift/commit/4a84baaaa3bc0fcbd049c44c8c0f4152577980cb))
* pin tamga-c workflow call to a release tag + fix stale CLAUDE.md claims ([bbc93bb](https://github.com/tamga-sh/tamga-swift/commit/bbc93bb42a6259cdf37ba90776f3a9f74c06cdca))
* scope the created iOS Simulator's runtime to the selected Xcode's own bundle ([341bd3f](https://github.com/tamga-sh/tamga-swift/commit/341bd3f859e22c69552de6e73494030fd70a55b0))
* select iOS Simulator destination via xcodebuild, not simctl ([f84dbc1](https://github.com/tamga-sh/tamga-swift/commit/f84dbc1f0fb3c8143fbba3dfda3fc5e9987d5942))
* use the Tamga-Package scheme for xcodebuild test, not Tamga ([20fbec1](https://github.com/tamga-sh/tamga-swift/commit/20fbec1b47a4780eaf93d836fb1c29005b3af962))
