// swift-tools-version:6.0
import PackageDescription

// MARK: - tamga-swift

// Official Swift SDK for Tamga, with Objective-C interoperability.
//
// Architecture (see CLAUDE.md for the full rationale):
//   TamgaCore (binary)  -- tamga-c's prebuilt XCFramework; ONLY the 4 crypto/offline-
//                          verification primitives (Ed25519 verify, AES-256-GCM open,
//                          HKDF-SHA256 derive, multi-scheme verify) cross this boundary.
//   CTamgaShim          -- C target that makes tamga.h Swift-importable via a modulemap.
//   Tamga               -- public Swift API. Hand-rolls its OWN HTTP transport on
//                          URLSession; does NOT delegate networking to tamga-c.
//   TamgaObjC           -- thin Objective-C interop wrapper over Tamga.
//   TamgaTests          -- Swift Testing (import Testing, NOT XCTest).
//
// LOCAL DEV OVERRIDE: tamga-c has not published a release yet, so the binaryTarget
// below is a placeholder that cannot resolve. Until tamga-c ships v0.1, comment out
// the `url:`/`checksum:` binaryTarget and use the `path:` one instead, pointed at a
// locally built XCFramework. See CLAUDE.md's "Local development" section for the
// exact build command. Do not commit the swap the other direction (path: -> url:)
// without confirming the checksum matches a real published release asset.

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
        // PLACEHOLDER: unresolvable until tamga-c publishes a v0.1 GitHub Release.
        // Swap for local development:
        //
        //   .binaryTarget(
        //       name: "TamgaCore",
        //       path: "../tamga-c/build/TamgaCore.xcframework"
        //   ),
        .binaryTarget(
            name: "TamgaCore",
            url: "https://github.com/tamga-sh/tamga-c/releases/download/vX.Y.Z/TamgaCore.xcframework.zip",
            checksum: "PLACEHOLDER_UNTIL_TAMGA_C_RELEASES"
        ),
        .target(
            name: "CTamgaShim",
            dependencies: ["TamgaCore"]
        ),
        .target(
            name: "Tamga",
            dependencies: ["CTamgaShim"]
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
