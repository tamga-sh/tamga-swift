// shim.c
//
// CTamgaShim has no implementation of its own -- it exists purely to make
// tamga-c's tamga.h importable from Swift via include/module.modulemap and
// include/shim.h (a thin #include re-export, see that file's header
// comment). `swift build`/`swift test` handle a modulemap-only C target
// with no .c sources without issue, but `xcodebuild`'s synthesized build
// graph does not: confirmed directly, `xcodebuild test -scheme
// Tamga-Package` failed with "Build input file cannot be found:
// .../CTamgaShim.o" -- it still expects an object file output from this
// target even though nothing needs to be compiled. This file exists only
// to give it one; it deliberately declares nothing.
