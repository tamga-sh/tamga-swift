// swift-tools-version:6.0
import PackageDescription

// MARK: - tamga-swift

// Official Swift SDK for Tamga. Integrate license activation, offline
// verification, and machine management into your Swift applications.
//
// SwiftPM's PackageDescription has no keywords/tags field, so the SDK fleet's
// canonical keyword set (licensing, software-licensing, license-key,
// activation, entitlements) has nowhere to live in this manifest. On Swift
// Package Index those come from the repository's own GitHub topics, which are
// set on the repository rather than in tracked files.
//
// Architecture (see CLAUDE.md for the full rationale):
//   Tamga       -- public Swift API: the HTTP client (TamgaClient/Transport)
//                  plus offline verification (license files, machine files,
//                  offline proofs), which needs no network at all.
//                  All crypto/offline-verification primitives (Ed25519 verify,
//                  AES-256-GCM open, HKDF-SHA256 derive, ECDSA-P256 and RSA
//                  verify) are native Swift on apple/swift-crypto -- see
//                  Sources/Tamga/Crypto/. No FFI boundary, no binary target.
//   TamgaObjC   -- Objective-C interop target. Builds and links, but exports no
//                  public interface yet.
//   TamgaTests  -- Swift Testing (import Testing, NOT XCTest).
//
// Until 2026-08-12 this package instead bound to tamga-c (a Rust reference
// implementation exposed through a C ABI) for the same 4 operations, via a
// TamgaCore binaryTarget + CTamgaShim C target. Deliberately replaced with a
// native reimplementation -- see CLAUDE.md's "Crypto Architecture" section
// for why.

// Linux support.
//
// `platforms:` only constrains Apple platforms; it says nothing about Linux, so this package
// nominally built for Linux while being impossible to compile there -- every Crypto/ file imported
// CryptoKit and Rsa.swift imported Security, both Apple-only. Moving to apple/swift-crypto fixes
// that with ONE code path rather than a `#if canImport(Security)` split: divergent per-platform
// crypto is precisely what produced the curve-confusion bug class this SDK family's audit found in
// 3 of 5 reimplementations, and a second implementation is a second place for it to reappear.
//
// swift-crypto is pinned to the 3.x line deliberately: 4.0.0 renames the `_CryptoExtras` module to
// `CryptoExtras`, which would break the RSA import below.
//
// `Crypto` forwards to CryptoKit on Apple platforms, so this is not an extra dependency there so
// much as a portable spelling of the same primitives. `_CryptoExtras` supplies RSA, which neither
// CryptoKit nor `Crypto` expose.
// TamgaObjC is Apple-only and is conditionally excluded below.
//
// A Package.swift manifest is Swift evaluated on the host, so `#if canImport(Darwin)` decides at
// manifest-evaluation time whether the Objective-C interop target exists at all. Without this the
// Linux build gets all the way through the Tamga module and then fails compiling TamgaObjC.m on
// `#import <Foundation/Foundation.h>` -- Objective-C interop simply does not exist on Linux, so
// there is nothing to conditionally compile *inside* the target either.
#if canImport(Darwin)
let objcProducts: [Product] = [.library(name: "TamgaObjC", targets: ["TamgaObjC"])]
let objcTargets: [Target] = [.target(name: "TamgaObjC", dependencies: ["Tamga"])]
#else
let objcProducts: [Product] = []
let objcTargets: [Target] = []
#endif

let package = Package(
    name: "Tamga",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "Tamga", targets: ["Tamga"]),
    ] + objcProducts,
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.13.0"),
    ],
    targets: [
        .target(
            name: "Tamga",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "TamgaTests",
            dependencies: [
                "Tamga",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
    ] + objcTargets
)
