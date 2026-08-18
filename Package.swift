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
//   Tamga       -- public Swift API. Offline verification (license files,
//                  machine files, offline proofs) is implemented; the HTTP
//                  client surface is not yet, and will hand-roll its own
//                  transport on URLSession when it lands.
//                  All 4 crypto/offline-verification primitives (Ed25519 verify,
//                  AES-256-GCM open, HKDF-SHA256 derive, multi-scheme verify) are native
//                  Swift, backed by CryptoKit + the Security framework -- see
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

let package = Package(
    name: "Tamga",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "Tamga", targets: ["Tamga"]),
        .library(name: "TamgaObjC", targets: ["TamgaObjC"]),
    ],
    targets: [
        .target(
            name: "Tamga"
        ),
        .target(
            name: "TamgaObjC",
            dependencies: ["Tamga"]
        ),
        .testTarget(
            name: "TamgaTests",
            dependencies: ["Tamga"]
        ),
    ]
)
