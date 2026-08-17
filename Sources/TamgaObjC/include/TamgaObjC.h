// TamgaObjC.h
//
// STUB -- scaffolding only. No implementation yet.
//
// Thin Objective-C interoperability wrapper over the `Tamga` Swift target,
// so that this package covers both Swift and Objective-C consumers. This
// target exists so Objective-C consumers (older macOS/iOS codebases that
// have not adopted Swift, or mixed-language apps) can call Tamga without
// depending on Swift's ObjC-bridging quirks for the public Swift API
// directly (e.g. Swift enums with associated values, `async`/`await`, and
// `Result<T, TamgaError>` are not directly ObjC-visible).
//
// Intended contents once implemented: an `@interface TamgaObjC` (or similar
// class-cluster wrapper) exposing completion-handler-based equivalents of
// `TamgaClient`'s core methods (validateByKey, checkOutLicense, etc.), plus
// ObjC-visible model classes bridging `License`/`Machine`/`ValidationCode`.
// No example project exists for it yet.

#import <Foundation/Foundation.h>

//! Project version number for TamgaObjC.
FOUNDATION_EXPORT double TamgaObjCVersionNumber;

//! Project version string for TamgaObjC.
FOUNDATION_EXPORT const unsigned char TamgaObjCVersionString[];

// Intentionally no public interface yet. Implementation deferred to a future
// release.
