# Changelog

## [1.3.3](https://github.com/tamga-sh/tamga-swift/compare/v1.3.2...v1.3.3) (2026-09-05)


### Bug Fixes

* **checkout:** reject a fast-path machine whose fingerprint doesn't match ([8cf2eba](https://github.com/tamga-sh/tamga-swift/commit/8cf2ebabb425b0e6c30def99ff358019a1f13bb5))
* numeric status, error meta, meta.machineId fast path (1.3.3) ([8d0c03c](https://github.com/tamga-sh/tamga-swift/commit/8d0c03c3a2a1ec25f4274fede88bfa3e8316b4bb))
* tolerate a numeric error status, carry the error meta, and adopt the machine a 409 names ([45159e7](https://github.com/tamga-sh/tamga-swift/commit/45159e7d6877634012450d1c646a8d56203aa5fc))

## [1.3.2](https://github.com/tamga-sh/tamga-swift/compare/v1.3.1...v1.3.2) (2026-08-21)


### Bug Fixes

* artifact read/download, fingerprint canonicalisation, and two corrected claims ([1e0f95e](https://github.com/tamga-sh/tamga-swift/commit/1e0f95e4f3939a1d29c5804ac210688383bf041b))
* canonicalise machine fingerprints instead of sending them byte-for-byte ([e387dd3](https://github.com/tamga-sh/tamga-swift/commit/e387dd3bc814e6b832ce0f01312083fdcbc9981c))
* say what the key-id lenience actually decides, and pin it with a test ([49cc909](https://github.com/tamga-sh/tamga-swift/commit/49cc909126e9497ac0095e16c53cd9f1d59c34eb))
* validate the download URL's scheme, and stop asserting a redirect rule that is not true ([d95ae06](https://github.com/tamga-sh/tamga-swift/commit/d95ae06dd6afc862af1e4dbeb307b3491ba75ded))
* wrap artifact read and download, now that a licence key can reach them ([f210da3](https://github.com/tamga-sh/tamga-swift/commit/f210da355187628079d90bc66bc777d7bd578fa3))

## [1.3.1](https://github.com/tamga-sh/tamga-swift/compare/v1.3.0...v1.3.1) (2026-08-21)


### Bug Fixes

* keep the install snippet's version current at release ([6ce159b](https://github.com/tamga-sh/tamga-swift/commit/6ce159b667de99509c2935b69dce9b8b356a4889))
* keep the install snippet's version current at release ([630f433](https://github.com/tamga-sh/tamga-swift/commit/630f433dafbf7c66157716f4854224cb92c6ad2b))

## [1.3.0](https://github.com/tamga-sh/tamga-swift/compare/v1.2.1...v1.3.0) (2026-08-21)


### Features

* document key rotation and the cookie transport's Origin ([b1a722f](https://github.com/tamga-sh/tamga-swift/commit/b1a722f9ab031c0a1fcbb7591af1b8bc7ecebb2c))
* kid-aware verification and a session cookie that authenticates ([758880f](https://github.com/tamga-sh/tamga-swift/commit/758880f5df2e422ecdae1ff14450a6178caa11fa))
* send the Origin that makes session-cookie auth authenticate ([7d88038](https://github.com/tamga-sh/tamga-swift/commit/7d880388897c17bf404ca2b4531511adce6c725e))
* tell a rotated signing key apart from a forged file ([d3e1687](https://github.com/tamga-sh/tamga-swift/commit/d3e1687da30a3c98a28910c2e3e56bf4773b2533))


### Bug Fixes

* let release-please manage sdkVersion, which the User-Agent sends ([#24](https://github.com/tamga-sh/tamga-swift/issues/24)) ([bfa8aa2](https://github.com/tamga-sh/tamga-swift/commit/bfa8aa20ece579f546365e318151194d07497eb6))

## [1.2.1](https://github.com/tamga-sh/tamga-swift/compare/v1.2.0...v1.2.1) (2026-08-21)


### Bug Fixes

* add the endpoint surface the SDK was missing (health, auto-update, reads, re-activation, process delete) ([6882201](https://github.com/tamga-sh/tamga-swift/commit/6882201efee0eec0548fbc279a13d6782e79fd0b))
* align the SDK with the current tamga-api server contract ([8026a28](https://github.com/tamga-sh/tamga-swift/commit/8026a282037789d2e625abe4f926a68cff450ed7))
* align the SDK with the current tamga-api server contract ([321f83f](https://github.com/tamga-sh/tamga-swift/commit/321f83fb49fba02c7b027c50d453872aa9e2bc33))
* bound the ping interval by rate, not by sign ([66048ae](https://github.com/tamga-sh/tamga-swift/commit/66048aee826b7d8193b8e4bbbea0f84ddde24a2b))
* bring the docs in line with the endpoints this SDK now has ([7e291c0](https://github.com/tamga-sh/tamga-swift/commit/7e291c0c15cd440025b97a62d94c737dbd56241f))
* call /v1/health anonymously, or it 401s on a default server ([9bea401](https://github.com/tamga-sh/tamga-swift/commit/9bea401769f305abddd7c06bd5691fc6ac551fa1))
* correct the DEAD heartbeat-status guidance, which was backwards ([c34001f](https://github.com/tamga-sh/tamga-swift/commit/c34001f9d8e69f56bf41cf1b64c9ebcc86be61c9))
* correct the ECDSA curve-check rationale and cover the bare-point branch ([c904f72](https://github.com/tamga-sh/tamga-swift/commit/c904f72b9c09644e99dde05fb6feb9eba6399ab3))
* correct the false "hardcoded 600s heartbeat window" claim ([be705b0](https://github.com/tamga-sh/tamga-swift/commit/be705b04861922b7f9647d688c2ff1a50a59a407))
* correct two doc claims in this branch that do not survive checking ([74ac946](https://github.com/tamga-sh/tamga-swift/commit/74ac94629e3224a9ce133cb09ae31a18fb2dcc13))
* expose the auto-update check, and name its "no" honestly ([9edb817](https://github.com/tamga-sh/tamga-swift/commit/9edb8170cb4f62bfa3299a4b3458def843d99dad))
* expose the licence, policy and machine reads a client cannot work without ([8585968](https://github.com/tamga-sh/tamga-swift/commit/85859687f434ebfe77b8c58a15b0ddf389610644))
* give a re-activation a way out of the 409 it dead-ends on ([7cf440f](https://github.com/tamga-sh/tamga-swift/commit/7cf440f4540c5ec86d2c09c780a0c2f324a45dd5))
* keep README's ECDSA note in line with what each check actually does ([99beb4c](https://github.com/tamga-sh/tamga-swift/commit/99beb4c878f86867d512bf87b9e99f9939374b8e))
* let a process registration be deleted, since nothing server-side ever does ([bc06cae](https://github.com/tamga-sh/tamga-swift/commit/bc06cae6c3fc5ee04b4162b4e39d7e8a698f3404))
* let Transport reach a route that is not under an account ([c1bb958](https://github.com/tamga-sh/tamga-swift/commit/c1bb95843f370f4e876d089dbe4bee752ff02893))
* make windowSeconds(for:) mirror the server exactly, as it claims to ([cec78b7](https://github.com/tamga-sh/tamga-swift/commit/cec78b77e5d3956c84ff0be24c3687dea3838c83))
* nest RouteScope in Transport, which is what the docs already call it ([cac1363](https://github.com/tamga-sh/tamga-swift/commit/cac136381b29422d5849784a0010e70f43ad34c4))
* reach /v1/health, which the account prefix made unreachable ([c39c8bc](https://github.com/tamga-sh/tamga-swift/commit/c39c8bce233247a6f8d5b105ac01c67b35304b36))
* size the machine heartbeat interval from the policy, not the 600s fallback ([e88398e](https://github.com/tamga-sh/tamga-swift/commit/e88398eadaabf926a966f29b62e2016239ea06fa))
* stop framing .dead as something a ping response can carry ([0cae60e](https://github.com/tamga-sh/tamga-swift/commit/0cae60e55e4ca797d07229a746dca4610288a400))
* stop SECURITY.md describing a version of this SDK that no longer exists ([dc7684d](https://github.com/tamga-sh/tamga-swift/commit/dc7684d2feba17a594d7f58602d767b28a3c04e4))
* verify machine files against the format the server actually emits ([71a24da](https://github.com/tamga-sh/tamga-swift/commit/71a24da7e198af61356a5718c5199b9847e7811e))
* verify machine files against the format the server actually emits ([fbefb46](https://github.com/tamga-sh/tamga-swift/commit/fbefb464ac8ab1827aaec2a8e880c39215386242))

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
