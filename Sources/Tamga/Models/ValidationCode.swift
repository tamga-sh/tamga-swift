import Foundation

/// The license validation result code returned as `meta.code` by all three
/// validation endpoints.
///
/// `code` is stable and is what callers should switch on. The sibling `detail`
/// field is human-readable text whose wording may change between server
/// versions -- never match on it.
///
/// All 24 wire values are modeled for schema completeness, but **only 14 are
/// reachable** against the server today; `isReachable` reports which. Do not
/// build product behaviour on an unreachable one. An unrecognized value decodes
/// to `.unknown` rather than failing, so a server-side addition can never break
/// a released SDK.
public enum ValidationCode: Equatable, Sendable {
    /// All checks passed. Reachable.
    case valid
    /// `license.suspended` is true. Reachable.
    case suspended
    /// The license expiry is in the past. Reachable.
    case expired
    /// Check-in is required and the window elapsed. Reachable.
    case overdue
    /// `scope.product` was set and did not match. Reachable.
    case productScopeMismatch
    /// `scope.policy` was set and did not match. Reachable.
    case policyScopeMismatch
    /// `scope.user` was set and did not match. Reachable.
    case userScopeMismatch
    /// `scope.environment` was set and did not match. Reachable.
    case environmentScopeMismatch
    /// Machine count exceeded the policy limit, as adjusted by the overage
    /// strategy. Reachable.
    case tooManyMachines
    /// Core count exceeded `policy.max_cores`. Reachable.
    case tooManyCores
    /// Memory exceeded `policy.max_memory`. Reachable.
    case tooMuchMemory
    /// Disk exceeded `policy.max_disk`. Reachable.
    case tooMuchDisk
    /// Process count exceeded `policy.max_processes`. Reachable.
    case tooManyProcesses
    /// Uses reached `max_uses`. Reachable. The comparison is a strict `>=` and
    /// overage strategies never apply to uses, unlike every other limit.
    case tooManyUses

    /// Unreachable: the handler returns a bare HTTP 404 rather than emitting
    /// this code.
    case notFound
    /// Unreachable: declared in the server's enum, never emitted.
    case banned
    /// Unreachable: declared in the server's enum, never emitted.
    case entitlementsMissing
    /// Unreachable: declared in the server's enum, never emitted.
    case tooManyUsers
    /// Unreachable: declared in the server's enum, never emitted.
    case heartbeatDead
    /// Unreachable: declared in the server's enum, never emitted.
    case heartbeatNotStarted
    /// Unreachable: `scope.fingerprint` is parsed server-side but never checked.
    case fingerprintScopeMismatch
    /// Unreachable: declared in the server's enum, never emitted.
    case componentsScopeMismatch
    /// Unreachable: `scope.checksum` is parsed server-side but never checked.
    case checksumScopeMismatch
    /// Unreachable: `scope.version` is parsed server-side but never checked.
    case versionScopeMismatch

    /// A code this SDK release does not recognize, carrying the raw wire value.
    case unknown(String)

    /// Every case with a fixed wire value, in the server's own order.
    static let knownValues: [(ValidationCode, String)] = [
        (.valid, "VALID"),
        (.suspended, "SUSPENDED"),
        (.expired, "EXPIRED"),
        (.overdue, "OVERDUE"),
        (.productScopeMismatch, "PRODUCT_SCOPE_MISMATCH"),
        (.policyScopeMismatch, "POLICY_SCOPE_MISMATCH"),
        (.userScopeMismatch, "USER_SCOPE_MISMATCH"),
        (.environmentScopeMismatch, "ENVIRONMENT_SCOPE_MISMATCH"),
        (.tooManyMachines, "TOO_MANY_MACHINES"),
        (.tooManyCores, "TOO_MANY_CORES"),
        (.tooMuchMemory, "TOO_MUCH_MEMORY"),
        (.tooMuchDisk, "TOO_MUCH_DISK"),
        (.tooManyProcesses, "TOO_MANY_PROCESSES"),
        (.tooManyUses, "TOO_MANY_USES"),
        (.notFound, "NOT_FOUND"),
        (.banned, "BANNED"),
        (.entitlementsMissing, "ENTITLEMENTS_MISSING"),
        (.tooManyUsers, "TOO_MANY_USERS"),
        (.heartbeatDead, "HEARTBEAT_DEAD"),
        (.heartbeatNotStarted, "HEARTBEAT_NOT_STARTED"),
        (.fingerprintScopeMismatch, "FINGERPRINT_SCOPE_MISMATCH"),
        (.componentsScopeMismatch, "COMPONENTS_SCOPE_MISMATCH"),
        (.checksumScopeMismatch, "CHECKSUM_SCOPE_MISMATCH"),
        (.versionScopeMismatch, "VERSION_SCOPE_MISMATCH")
    ]

    /// Maps a raw wire string, falling back to `.unknown` for anything
    /// unrecognized.
    public init(wireValue: String?) {
        guard let wireValue else {
            self = .unknown("")
            return
        }
        self = Self.knownValues.first { $0.1 == wireValue }?.0 ?? .unknown(wireValue)
    }

    /// This code's wire string.
    public var wireValue: String {
        if case .unknown(let raw) = self {
            return raw
        }
        return Self.knownValues.first { $0.0 == self }?.1 ?? ""
    }

    /// Whether the server can actually emit this code today. Useful for
    /// diagnostics; product logic should switch on the case itself.
    public var isReachable: Bool {
        switch self {
        case .valid, .suspended, .expired, .overdue,
             .productScopeMismatch, .policyScopeMismatch, .userScopeMismatch,
             .environmentScopeMismatch, .tooManyMachines, .tooManyCores,
             .tooMuchMemory, .tooMuchDisk, .tooManyProcesses, .tooManyUses:
            return true
        default:
            return false
        }
    }

    /// Whether this code means a policy limit was exceeded, which is the set
    /// that triggers `TamgaClient.activateMachine`'s rollback.
    public var isOverLimit: Bool {
        switch self {
        case .tooManyMachines, .tooManyCores, .tooMuchMemory, .tooMuchDisk, .tooManyProcesses:
            return true
        default:
            return false
        }
    }
}

/// The `{ts, valid, detail, code}` object returned alongside a license resource
/// by validate-by-key and validate-by-id, and returned as the *entire flat
/// body* of quick-validate.
public struct ValidationMeta: Equatable, Sendable {
    /// The server timestamp at which validation ran.
    public let ts: Date?
    /// Whether the license passed validation.
    public let valid: Bool
    /// Human-readable detail. Never match on this -- match on `code`.
    public let detail: String?
    /// The stable validation result code.
    public let code: ValidationCode
}

/// The wire shape of a validation meta block, decoded then flattened.
struct ValidationMetaWire: Decodable {
    let ts: Date?
    let valid: Bool?
    let detail: String?
    let code: String?

    var flattened: ValidationMeta {
        ValidationMeta(ts: ts, valid: valid ?? false, detail: detail,
                       code: ValidationCode(wireValue: code))
    }
}
