// shim.h -- thin re-export of tamga-c's tamga.h.
//
// tamga-c has published real GitHub Releases with built XCFramework-ready
// artifacts (starting v1.0.1) and build-xcframework.yml bundles its
// include/tamga.h into every platform slice of TamgaCore.xcframework via
// `xcodebuild -create-xcframework -headers ...` -- so tamga.h is available
// on the header search path of anything that depends on the TamgaCore
// binary target, this C target included.
//
// Do NOT hand-transcribe tamga.h's declarations here -- this re-exports the
// real header via #include so CTamgaShim can never silently drift from
// tamga-c's actual ABI. Sources/Tamga/FFI/*.swift wrappers (Ed25519Verifier,
// AesGcmCipher, HkdfDeriver, MultiSchemeVerifier) are the only Swift files
// permitted to `import CTamgaShim`.
//
// tamga-c's ABI-freeze commitment (see that repo's CLAUDE.md) still applies
// before depending on this for anything shipped: struct layout and function
// signature changes there require a version bump, no silent breaking
// changes -- this header always reflects whatever tamga-c release the
// resolved TamgaCore.xcframework was built from, nothing more.

#ifndef TAMGA_CTAMGASHIM_SHIM_H
#define TAMGA_CTAMGASHIM_SHIM_H

#include <tamga.h>

#endif /* TAMGA_CTAMGASHIM_SHIM_H */
