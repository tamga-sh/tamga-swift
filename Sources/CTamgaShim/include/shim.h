// shim.h -- thin re-export of tamga-c's tamga.h.
//
// STUB. tamga-c has not published a release yet, so there is no tamga.h to vendor
// or re-export. This header intentionally declares nothing.
//
// Once tamga-c v0.1 ships (frozen ABI, semver commitment -- see docs/sdk.md and
// this repo's CLAUDE.md), replace the body of this file with:
//
//   #include <tamga.h>
//
// Do NOT hand-transcribe tamga.h's declarations here -- re-export the real header
// via #include so CTamgaShim can never silently drift from tamga-c's actual ABI.
// Sources/Tamga/FFI/*.swift wrappers (Ed25519Verifier, AesGcmCipher, HkdfDeriver,
// MultiSchemeVerifier) are the only Swift files permitted to `import CTamgaShim`.

#ifndef TAMGA_CTAMGASHIM_SHIM_H
#define TAMGA_CTAMGASHIM_SHIM_H

// Intentionally empty until tamga-c v0.1 ships.

#endif /* TAMGA_CTAMGASHIM_SHIM_H */
