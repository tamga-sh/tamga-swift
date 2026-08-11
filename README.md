# Tamga

Official Swift SDK for Tamga, with Objective-C interoperability. Integrate
license activation and offline verification into your macOS and iOS
applications, built on the [tamga-c](https://github.com/tamga-sh/tamga-c)
core.

> **Status: pre-release scaffold.** This repository currently contains
> project structure and stub files only — no business logic, HTTP transport,
> or cryptographic verification is implemented yet, and it is blocked on
> `tamga-c`'s ABI freeze (see `CLAUDE.md`). The code snippets below show the
> intended API shape and are illustrative, not yet functional.

## Install

**Swift Package Manager** (git URL — Tamga has no central package registry
name reservation; SPM resolves packages by git URL, not by name):

```swift
.package(url: "https://github.com/tamga-sh/tamga-swift", from: "<version>")
```

Then add `Tamga` (and, if you need Objective-C interop, `TamgaObjC`) to your
target's dependencies:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "Tamga", package: "tamga-swift"),
    ]
)
```

## Quickstart

> Illustrative — matches the stub API shape scaffolded in this repository,
> not yet a working implementation.

### Swift

```swift
import Tamga

let client = TamgaClient(
    configuration: .init(
        accountId: "your-account-id",
        baseURL: URL(string: "https://api.tamga.sh")!
    )
)

let result = try await client.validateByKey("your-license-key")

switch result.code {
case .valid:
    print("License is valid")
case .expired, .suspended:
    print("License is not usable: \(result.code)")
default:
    print("Validation returned: \(result.code)")
}
```

### Objective-C

```objc
@import TamgaObjC;

TamgaObjC *client = [[TamgaObjC alloc] initWithAccountId:@"your-account-id"
                                                   baseURL:[NSURL URLWithString:@"https://api.tamga.sh"]];

[client validateLicenseByKey:@"your-license-key" completion:^(TamgaValidationResult *result, NSError *error) {
    if (error) {
        NSLog(@"Validation failed: %@", error);
        return;
    }
    NSLog(@"Validation code: %@", result.code);
}];
```

## Documentation

- [Tamga SDK protocol reference](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md) —
  the authoritative spec every field name, endpoint, and enum value in this
  SDK is taken from, including a "Known Server-Side Gaps" section describing
  which documented features are not actually reachable against the server
  yet.
- [`CLAUDE.md`](CLAUDE.md) — architecture, dev commands, and gotchas for
  contributors.

## License

MIT — see [LICENSE](LICENSE).
