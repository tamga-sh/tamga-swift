import Testing

@testable import Tamga

// SmokeTests.swift
//
// Confirms the `TamgaTests` target builds and runs under Swift Testing (NOT
// XCTest -- see CLAUDE.md for the rationale) and that `@testable import
// Tamga` resolves correctly. As of the native-crypto reimplementation
// (2026-08-12), the package graph is just Tamga -> TamgaObjC/TamgaTests --
// no binary target, no C shim.
//
// Real coverage lands area by area as each part of the SDK is implemented.
// The full intended layout of this tree is TransportAuthTests,
// LicenseValidationTests, CheckInTests, MachineManagementTests,
// ComponentTests, ProcessTests, EntitlementTests, plus Crypto/, Checkout/,
// Models/, and Support/ subdirectories.

@Suite("Smoke")
struct SmokeTests {
    @Test("package scaffold builds and the test target runs")
    func scaffoldBuilds() {
        #expect(true)
    }
}
