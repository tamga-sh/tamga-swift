// swift-tools-version:6.0
import PackageDescription

// MARK: - tamga-swift

// Official Swift SDK for Tamga, with Objective-C interoperability.
//
// Architecture (see CLAUDE.md for the full rationale):
//   Tamga       -- public Swift API. Hand-rolls its own HTTP transport on URLSession.
//                  All 4 crypto/offline-verification primitives (Ed25519 verify,
//                  AES-256-GCM open, HKDF-SHA256 derive, multi-scheme verify) are native
//                  Swift, backed by CryptoKit + the Security framework -- see
//                  Sources/Tamga/Crypto/. No FFI boundary, no binary target.
//   TamgaObjC   -- thin Objective-C interop wrapper over Tamga.
//   TamgaTests  -- Swift Testing (import Testing, NOT XCTest).
//
// Until 2026-08-12 this package instead bound to tamga-c (a Rust reference
// implementation exposed through a C ABI) for the same 4 operations, via a
// TamgaCore binaryTarget + CTamgaShim C target. Deliberately replaced with a
// native reimplementation -- see CLAUDE.md's "Crypto Architecture" section
// for why, and docs/plans/tamga-swift.plan.md for the full history.

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
