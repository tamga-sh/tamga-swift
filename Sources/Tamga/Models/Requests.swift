import Foundation

/// Options for registering a machine against a license. `fingerprint` and
/// `licenseId` are required; everything else is optional.
///
/// Machine, core, memory and disk limits are **not** checked at creation time.
/// They surface only later, through validation -- see
/// `TamgaClient.activateMachine`, which creates, validates, and rolls back.
public struct CreateMachineOptions: Equatable, Sendable {
    /// The machine fingerprint. Required.
    public var fingerprint: String
    /// The id of the license this machine is registered against. Required.
    public var licenseId: String
    /// Display name.
    public var name: String?
    /// Reported IP address.
    public var ip: String?
    /// Reported hostname.
    public var hostname: String?
    /// Reported platform identifier.
    public var platform: String?
    /// Reported core count, which validation checks against the policy limit.
    public var cores: Int?
    /// Reported memory in bytes.
    public var memory: Int64?
    /// Reported disk in bytes.
    public var disk: Int64?
    /// Arbitrary metadata.
    public var metadata: [String: JSONValue]?

    /// Creates options for a machine.
    public init(
        fingerprint: String,
        licenseId: String,
        name: String? = nil,
        ip: String? = nil,
        hostname: String? = nil,
        platform: String? = nil,
        cores: Int? = nil,
        memory: Int64? = nil,
        disk: Int64? = nil,
        metadata: [String: JSONValue]? = nil
    ) {
        self.fingerprint = fingerprint
        self.licenseId = licenseId
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.platform = platform
        self.cores = cores
        self.memory = memory
        self.disk = disk
        self.metadata = metadata
    }

    /// The JSON:API request body.
    ///
    /// Machine creation is the **only** create in this API that is enveloped --
    /// components and processes post flat bodies. Do not "normalize" this: the
    /// asymmetry is real server behaviour.
    ///
    /// `metadata` defaults to an empty object rather than null, matching the
    /// rest of the SDK fleet.
    var requestBody: JSONValue {
        let attributes: [String: JSONValue] = [
            "fingerprint": .string(fingerprint),
            "name": name.map(JSONValue.string) ?? .null,
            "ip": ip.map(JSONValue.string) ?? .null,
            "hostname": hostname.map(JSONValue.string) ?? .null,
            "platform": platform.map(JSONValue.string) ?? .null,
            "cores": cores.map { .int(Int64($0)) } ?? .null,
            "memory": memory.map(JSONValue.int) ?? .null,
            "disk": disk.map(JSONValue.int) ?? .null,
            "metadata": .object(metadata ?? [:]),
        ]
        return .object([
            "data": .object([
                "type": .string("machines"),
                "attributes": .object(attributes),
                "relationships": .object([
                    "license": .object([
                        "data": .object([
                            "type": .string("licenses"),
                            "id": .string(licenseId),
                        ]),
                    ]),
                ]),
            ]),
        ])
    }
}

/// Options for registering a component against a machine. All three fields are
/// required.
public struct CreateComponentOptions: Equatable, Sendable {
    /// The id of the machine this component belongs to.
    public var machineId: String
    /// The component's fingerprint.
    public var fingerprint: String
    /// The component's display name.
    public var name: String
    /// Arbitrary metadata.
    public var metadata: [String: JSONValue]?

    /// Creates options for a component.
    public init(machineId: String, fingerprint: String, name: String,
                metadata: [String: JSONValue]? = nil) {
        self.machineId = machineId
        self.fingerprint = fingerprint
        self.name = name
        self.metadata = metadata
    }

    /// The request body. **Flat, not enveloped** -- unlike machine creation.
    var requestBody: JSONValue {
        .object([
            "machine_id": .string(machineId),
            "fingerprint": .string(fingerprint),
            "name": .string(name),
            "metadata": .object(metadata ?? [:]),
        ])
    }
}

/// Options for registering a process against a machine.
///
/// `pid` is a `String` because the server types it that way on the wire. A
/// caller holding a numeric process id must stringify it at the call site --
/// this SDK will not coerce it silently, so the string-not-integer contract
/// stays visible where it matters.
public struct CreateProcessOptions: Equatable, Sendable {
    /// The id of the machine this process belongs to.
    public var machineId: String
    /// The operating-system process id, as a string.
    public var pid: String
    /// Arbitrary metadata.
    public var metadata: [String: JSONValue]?

    /// Creates options for a process.
    public init(machineId: String, pid: String, metadata: [String: JSONValue]? = nil) {
        self.machineId = machineId
        self.pid = pid
        self.metadata = metadata
    }

    /// The request body. Flat, not enveloped.
    var requestBody: JSONValue {
        .object([
            "machine_id": .string(machineId),
            "pid": .string(pid),
            "metadata": .object(metadata ?? [:]),
        ])
    }
}

/// Options for checking out an offline `.lic` or `.machine` certificate.
///
/// The endpoint has two variants. `GET` returns the raw PEM as
/// `application/octet-stream`; `POST` returns a JSON:API resource whose
/// `attributes.certificate` holds the same PEM. Both yield the same
/// certificate, so `usePost` is a transport preference, not a behavioural one.
public struct CheckOutOptions: Equatable, Sendable {
    /// The largest time-to-live the server accepts, in seconds -- one year.
    public static let maxTtlSeconds = 31_536_000

    /// Requested time-to-live in seconds, or `nil` for the server default.
    public var ttl: Int?
    /// Whether to request an encrypted certificate.
    public var encrypt: Bool
    /// Whether to use the JSON:API POST variant instead of the raw GET variant.
    public var usePost: Bool

    /// Creates checkout options.
    public init(ttl: Int? = nil, encrypt: Bool = false, usePost: Bool = false) {
        self.ttl = ttl
        self.encrypt = encrypt
        self.usePost = usePost
    }

    /// Validates the time-to-live client-side, so an obviously bad value fails
    /// before a round trip rather than as a 422.
    func validate() throws {
        guard let ttl else { return }
        guard ttl > 0, ttl <= Self.maxTtlSeconds else {
            throw TamgaCheckoutError.ttlInvalid(
                "ttl must be greater than 0 and at most \(Self.maxTtlSeconds) seconds, got \(ttl)."
            )
        }
    }

    /// The request body for the POST variant.
    var requestBody: JSONValue {
        .object([
            "meta": .object([
                "encrypt": .bool(encrypt),
                "ttl": ttl.map { .int(Int64($0)) } ?? .null,
            ]),
        ])
    }
}

/// Options for validate-by-id.
public struct ValidateOptions: Equatable, Sendable {
    /// Scope constraints, or `nil` when unconstrained.
    public var scope: Scope?
    /// Asks the server not to update the license's last-validated timestamp,
    /// which is useful for a background check that should not look like user
    /// activity.
    public var skipTouch: Bool

    /// Creates validate options.
    public init(scope: Scope? = nil, skipTouch: Bool = false) {
        self.scope = scope
        self.skipTouch = skipTouch
    }

    /// The request body, omitting an unset or empty scope entirely.
    var requestBody: JSONValue {
        var meta: [String: JSONValue] = ["skip_touch": .bool(skipTouch)]
        if let scope, !scope.isEmpty {
            meta["scope"] = scope.requestValue
        }
        return .object(["meta": .object(meta)])
    }
}

/// A license together with the validation verdict returned alongside it.
public struct ValidationResult: Equatable, Sendable {
    /// The license resource.
    public let license: License
    /// The validation verdict. Branch on `meta.code`.
    public let meta: ValidationMeta

    /// Whether validation passed.
    public var isValid: Bool { meta.valid }
}

/// The outcome of a successful machine activation: the created machine plus the
/// validation verdict that cleared it.
public struct ActivationResult: Equatable, Sendable {
    /// The newly registered machine.
    public let machine: Machine
    /// The validation verdict that cleared the activation.
    public let meta: ValidationMeta
}

/// The outcome of generating a machine offline proof.
public struct OfflineProofResult: Equatable, Sendable {
    /// The machine the proof was generated for.
    public let machine: Machine
    /// The proof string, beginning with the `v1x0.` version prefix.
    public let proof: String?
}
