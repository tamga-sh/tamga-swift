import Foundation

/// `Policy.swift`
///
/// The key/checkout signing algorithm configured on a license's policy.
/// `.none` means the policy has no scheme set -- a legacy plain key string,
/// unsigned.
public enum LicenseScheme: String, Equatable, Sendable {
    /// No scheme configured -- legacy plain key string, unsigned.
    case none = ""
    /// Wire value `ED25519_SIGN`. Also the sole scheme used for license
    /// checkout (`Checkout/LicenseFile.swift`), independent of this field.
    case ed25519Sign = "ED25519_SIGN"
    /// Wire value `RSA_2048_PKCS1_SIGN`.
    case rsa2048Pkcs1Sign = "RSA_2048_PKCS1_SIGN"
    /// Wire value `RSA_2048_PKCS1_PSS_SIGN`.
    case rsa2048Pkcs1PssSign = "RSA_2048_PKCS1_PSS_SIGN"
    /// Wire value `ECDSA_P256_SIGN`.
    case ecdsaP256Sign = "ECDSA_P256_SIGN"
    /// Wire value `RSA_2048_JWT_RS256`. Explicitly rejected server-side for
    /// machine files (`422 SCHEME_NOT_SUPPORTED`) -- `MachineFile` must throw
    /// rather than attempt JWT/RS256 verification.
    case rsa2048JwtRs256 = "RSA_2048_JWT_RS256"

    /// An empty string or missing value maps to `.none` (legacy unsigned key).
    public init(wireValue: String?) {
        self = LicenseScheme(rawValue: wireValue ?? "") ?? .none
    }
}

/// How far past a numeric limit a license may go before validation fails.
///
/// Applies to machines, cores, memory, disk and processes -- **never** to
/// `uses`, which the server always compares strictly.
public enum OverageStrategy: Equatable, Sendable {
    /// Enforces the limit strictly: `count <= max`.
    case noOverage
    /// Allows up to 125% of the limit.
    case allow125x
    /// Allows up to 150% of the limit.
    case allow15x
    /// Allows up to 200% of the limit.
    case allow2x
    /// Skips limit enforcement entirely.
    case alwaysAllow

    static let knownValues: [(OverageStrategy, String)] = [
        (.noOverage, "NO_OVERAGE"),
        (.allow125x, "ALLOW_1_25X_OVERAGE"),
        (.allow15x, "ALLOW_1_5X_OVERAGE"),
        (.allow2x, "ALLOW_2X_OVERAGE"),
        (.alwaysAllow, "ALWAYS_ALLOW_OVERAGE")
    ]

    /// Maps a wire string, falling back to `.noOverage`.
    ///
    /// That fallback is what handles the real-world policy-create default
    /// `"DENY_ACCESS"` -- a string that is not a variant at all, and which the
    /// server itself treats as no overage. Read literally it looks maximally
    /// restrictive and means the opposite.
    public init(wireValue: String?) {
        guard let wireValue else {
            self = .noOverage
            return
        }
        self = Self.knownValues.first { $0.1 == wireValue }?.0 ?? .noOverage
    }

    /// Whether `count` is permitted against `max` under this strategy,
    /// mirroring the server's own floating-point comparison so a client-side
    /// pre-check reaches the identical verdict.
    public func allows(count: Int64, max: Int64) -> Bool {
        switch self {
        case .alwaysAllow:
            return true
        case .noOverage:
            return count <= max
        case .allow125x:
            return Double(count) <= Double(max) * 1.25
        case .allow15x:
            return Double(count) <= Double(max) * 1.5
        case .allow2x:
            return Double(count) <= Double(max) * 2.0
        }
    }
}

/// What happens to a machine row once its heartbeat window elapses.
public enum HeartbeatCullStrategy: String, Equatable, Sendable {
    /// Deletes the machine row once dead. The server's default.
    case deactivateDead = "DEACTIVATE_DEAD"
    /// Keeps the dead machine row in place.
    case keepDead = "KEEP_DEAD"

    /// Maps a wire string, falling back to `.deactivateDead`.
    public init(wireValue: String?) {
        self = HeartbeatCullStrategy(rawValue: wireValue ?? "") ?? .deactivateDead
    }
}

/// The grace window after a machine's heartbeat window elapses during which a
/// fresh ping revives it rather than the cull strategy taking effect.
public enum HeartbeatResurrectionStrategy: String, Equatable, Sendable {
    /// No grace window.
    case noRevive = "NO_REVIVE"
    /// One minute of grace.
    case oneMinute = "1_MINUTE_REVIVE"
    /// Two minutes of grace.
    case twoMinutes = "2_MINUTE_REVIVE"
    /// Five minutes of grace.
    case fiveMinutes = "5_MINUTE_REVIVE"
    /// Ten minutes of grace.
    case tenMinutes = "10_MINUTE_REVIVE"
    /// Fifteen minutes of grace.
    case fifteenMinutes = "15_MINUTE_REVIVE"
    /// Always revive, with no time bound.
    case always = "ALWAYS_REVIVE"

    /// Maps a wire string, falling back to `.noRevive`.
    ///
    /// That fallback is what handles the real-world policy-create default
    /// `"NO_RESURRECTION"`, which is not a variant and which the server treats
    /// as no revival.
    public init(wireValue: String?) {
        self = HeartbeatResurrectionStrategy(rawValue: wireValue ?? "") ?? .noRevive
    }
}

/// The check-in cadence unit.
///
/// Its wire values are **lowercase** (`day`/`week`/`month`/`year`), the single
/// casing exception among the protocol's otherwise uppercase enums.
public enum CheckInInterval: String, Equatable, Sendable {
    /// Wire value `day`.
    case day
    /// Wire value `week`.
    case week
    /// Wire value `month`.
    case month
    /// Wire value `year`.
    case year
}

/// The policy attached to a license.
///
/// **`max_memory` and `max_disk` are deliberately absent.** The server's GET
/// response omits both even though validation enforces them, so no client can
/// introspect those two limits -- it can only observe `.tooMuchMemory` or
/// `.tooMuchDisk` after the fact. They are not modeled at all rather than
/// modeled as perpetually-nil fields.
///
/// **Three strategy fields keep their raw string alongside a normalized
/// value.** Freshly created policies really do report `"DENY_ACCESS"` for
/// `overage_strategy` and `"NO_RESURRECTION"` for
/// `heartbeat_resurrection_strategy` -- neither is a real variant, and the
/// server itself treats both as the permissive case. Always read the
/// normalized property; the raw one is there for diagnostics.
public struct Policy: Equatable, Sendable {
    /// The policy's unique id.
    public let id: String
    /// The policy's display name.
    public let name: String?
    /// The id of the product this policy belongs to.
    public let productId: String?
    /// The key/checkout signing scheme configured on this policy.
    public let scheme: LicenseScheme
    /// The machine limit, or `nil` when unlimited.
    public let maxMachines: Int?
    /// The core limit, or `nil` when unlimited.
    public let maxCores: Int?
    /// The process limit, or `nil` when unlimited.
    public let maxProcesses: Int?
    /// The user limit, or `nil` when unlimited.
    public let maxUsers: Int?
    /// The use limit. Uses ignore the overage strategy.
    public let maxUses: Int?
    /// The license duration in seconds, or `nil` when perpetual.
    public let duration: Int64?
    /// `policy.heartbeat_duration`. **Do not derive a ping interval from
    /// this.** The server ignores it: the machine heartbeat window is a
    /// hardcoded 600 seconds.
    public let heartbeatDuration: Int?
    /// How many `checkInInterval` units make up one check-in period.
    public let checkInIntervalCount: Int?
    /// The check-in cadence unit.
    public let checkInInterval: CheckInInterval?
    /// The normalized overage strategy. Prefer this over `overageStrategyRaw`.
    public let overageStrategy: OverageStrategy
    /// The raw `overage_strategy` wire string, for diagnostics.
    public let overageStrategyRaw: String?
    /// The normalized cull strategy.
    public let heartbeatCullStrategy: HeartbeatCullStrategy
    /// The normalized resurrection strategy.
    public let heartbeatResurrectionStrategy: HeartbeatResurrectionStrategy
    /// The raw `heartbeat_resurrection_strategy` wire string, for diagnostics.
    public let heartbeatResurrectionStrategyRaw: String?
    /// Free text server-side: `RESTRICT_ACCESS` (default), `MAINTAIN_ACCESS`,
    /// `ALLOW_ACCESS`.
    public let expirationStrategy: String?
    /// Free text server-side: `FROM_EXPIRY` (default), `FROM_NOW`.
    public let renewalBasis: String?
    /// Free text server-side: `TOKEN` (default), `LICENSE`, `MIXED`.
    public let authenticationStrategy: String?
    /// Whether licences under this policy must periodically check in.
    public let requireCheckIn: Bool
    /// Whether machines under this policy must send heartbeats.
    public let requireHeartbeat: Bool
    /// Whether checkout files under this policy are encrypted.
    public let encrypted: Bool
    /// Whether licences under this policy are floating.
    public let floating: Bool
    /// Whether licences under this policy are strict.
    public let strict: Bool
    /// Whether this policy is protected.
    public let isProtected: Bool
    /// When the policy was created.
    public let created: Date?
    /// When the policy was last updated.
    public let updated: Date?
    /// Arbitrary key/value metadata.
    public let metadata: [String: JSONValue]?

    static func fromResource(_ resource: JSONAPIResource<PolicyAttributes>) -> Policy {
        let attrs = resource.attributes
        return Policy(
            id: resource.id,
            name: attrs?.name,
            productId: attrs?.productId,
            scheme: LicenseScheme(wireValue: attrs?.scheme),
            maxMachines: attrs?.maxMachines,
            maxCores: attrs?.maxCores,
            maxProcesses: attrs?.maxProcesses,
            maxUsers: attrs?.maxUsers,
            maxUses: attrs?.maxUses,
            duration: attrs?.duration,
            heartbeatDuration: attrs?.heartbeatDuration,
            checkInIntervalCount: attrs?.checkInIntervalCount,
            checkInInterval: attrs?.checkInInterval.flatMap(CheckInInterval.init(rawValue:)),
            overageStrategy: OverageStrategy(wireValue: attrs?.overageStrategy),
            overageStrategyRaw: attrs?.overageStrategy,
            heartbeatCullStrategy: HeartbeatCullStrategy(wireValue: attrs?.heartbeatCullStrategy),
            heartbeatResurrectionStrategy: HeartbeatResurrectionStrategy(
                wireValue: attrs?.heartbeatResurrectionStrategy),
            heartbeatResurrectionStrategyRaw: attrs?.heartbeatResurrectionStrategy,
            expirationStrategy: attrs?.expirationStrategy,
            renewalBasis: attrs?.renewalBasis,
            authenticationStrategy: attrs?.authenticationStrategy,
            requireCheckIn: attrs?.requireCheckIn ?? false,
            requireHeartbeat: attrs?.requireHeartbeat ?? false,
            encrypted: attrs?.encrypted ?? false,
            floating: attrs?.floating ?? false,
            strict: attrs?.strict ?? false,
            isProtected: attrs?.protected ?? false,
            created: attrs?.created,
            updated: attrs?.updated,
            metadata: attrs?.metadata
        )
    }
}

/// The JSON:API `attributes` bag for a policy resource.
struct PolicyAttributes: Decodable {
    let name: String?
    let productId: String?
    let scheme: String?
    let maxMachines: Int?
    let maxCores: Int?
    let maxProcesses: Int?
    let maxUsers: Int?
    let maxUses: Int?
    let duration: Int64?
    let heartbeatDuration: Int?
    let checkInIntervalCount: Int?
    let checkInInterval: String?
    let overageStrategy: String?
    let heartbeatCullStrategy: String?
    let heartbeatResurrectionStrategy: String?
    let expirationStrategy: String?
    let renewalBasis: String?
    let authenticationStrategy: String?
    let requireCheckIn: Bool?
    let requireHeartbeat: Bool?
    let encrypted: Bool?
    let floating: Bool?
    let strict: Bool?
    let protected: Bool?
    let created: Date?
    let updated: Date?
    let metadata: [String: JSONValue]?
}
