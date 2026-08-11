import Testing

@testable import Tamga

// SmokeTests.swift
//
// STUB -- scaffolding only. Confirms the `TamgaTests` target builds and runs
// under Swift Testing (NOT XCTest -- see CLAUDE.md for the rationale) and
// that `@testable import Tamga` resolves correctly through the package
// graph (Tamga -> CTamgaShim -> TamgaCore binary target).
//
// Real coverage lands per-section as each part of
// docs/plans/tamga-swift.plan.md is implemented -- see the Tests/TamgaTests/
// tree in the plan's Section A file list for the full intended layout
// (TransportAuthTests, LicenseValidationTests, CheckInTests,
// MachineManagementTests, ComponentTests, ProcessTests, EntitlementTests,
// ProofTests, ErrorModelTests, plus FFI/, Checkout/, Models/, and Support/
// subdirectories).

@Suite("Smoke")
struct SmokeTests {
    @Test("package scaffold builds and the test target runs")
    func scaffoldBuilds() {
        #expect(true)
    }
}
