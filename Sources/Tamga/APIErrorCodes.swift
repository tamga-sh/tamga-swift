import Foundation

/// The server error codes this SDK recognizes by name, plus the mapping from a
/// create-time policy-limit rejection to its validate-time `ValidationCode`.
///
/// These are `String` constants rather than an enum on purpose. The stable
/// identifier on the wire is `errors[].code`, which arrives on
/// `TamgaError.APIError.code`; a closed Swift enum would have to grow a case for
/// every future server code and would turn an unrecognized one into a decode
/// failure. Compare against these constants, never against `detail`.
///
/// ```swift
/// catch let error as TamgaError {
///     if error.apiCode == TamgaAPIErrorCode.licenseNotAllowed {
///         // The policy's authentication_strategy does not permit license-key
///         // auth. Retrying will not help -- this is a configuration
///         // precondition, not a transient failure.
///     }
/// }
/// ```
public enum TamgaAPIErrorCode {
    // MARK: Create-time policy limits (HTTP 422)

    /// `POST /machines` refused: the licence is at `policy.max_machines`.
    ///
    /// Equivalent to validation's `TOO_MANY_MACHINES`.
    public static let machineLimitExceeded = "MACHINE_LIMIT_EXCEEDED"

    /// `POST /machines` refused: the licence is at `policy.max_cores`.
    ///
    /// Equivalent to validation's `TOO_MANY_CORES`.
    public static let coreLimitExceeded = "CORE_LIMIT_EXCEEDED"

    /// `POST /machines` refused: the licence is at `policy.max_memory`.
    ///
    /// Equivalent to validation's `TOO_MUCH_MEMORY`. Remember that `memory` is
    /// reported in **megabytes** -- a caller sending bytes inflates the licence's
    /// running total by a factor of 1,048,576 and trips this on the next
    /// activation.
    public static let memoryLimitExceeded = "MEMORY_LIMIT_EXCEEDED"

    /// `POST /machines` refused: the licence is at `policy.max_disk`.
    ///
    /// Equivalent to validation's `TOO_MUCH_DISK`. `disk` is in **megabytes**
    /// too.
    public static let diskLimitExceeded = "DISK_LIMIT_EXCEEDED"

    /// `POST /processes` refused: the machine is at `policy.max_processes`.
    ///
    /// Equivalent to validation's `TOO_MANY_PROCESSES`.
    public static let tooManyProcesses = "TOO_MANY_PROCESSES"

    // MARK: License-state authentication rejections (HTTP 401)

    /// The licence authenticated against is suspended.
    public static let licenseSuspended = "LICENSE_SUSPENDED"

    /// The licence authenticated against has expired **and** its policy's
    /// `expiration_strategy` is `REVOKE_ACCESS`.
    ///
    /// Under `MAINTAIN_ACCESS`, `ALLOW_ACCESS` and `RESTRICT_ACCESS` an expired
    /// licence still authenticates and the expiry surfaces as validation's
    /// `EXPIRED` instead.
    public static let licenseExpired = "LICENSE_EXPIRED"

    /// License-key authentication is not permitted by the policy.
    ///
    /// The policy's `authentication_strategy` must be `LICENSE` or `MIXED` for
    /// `AuthTransport.licenseKey` / `.basicLicenseKey` to authenticate. The
    /// column defaults to `TOKEN`, and `NONE` behaves like `TOKEN` at this gate,
    /// so **license-key auth is off by default**.
    ///
    /// This is a configuration precondition, not a transient auth failure. Do
    /// not retry it and do not prompt for a different key.
    public static let licenseNotAllowed = "LICENSE_NOT_ALLOWED"

    // MARK: Request-shape rejections (HTTP 422)

    /// `meta.scope.version` or `meta.scope.checksum` was present on a validate
    /// request. The server rejects the **whole call** rather than ignoring the
    /// field, so no verdict comes back at all.
    ///
    /// This SDK no longer emits either field, so a caller setting them degrades
    /// to a working validate rather than a hard failure. See `Scope`.
    public static let scopeNotSupported = "SCOPE_NOT_SUPPORTED"

    /// `TamgaClient.downloadArtifact(_:ttl:)` asked for a presigned-URL
    /// lifetime outside `[60s, 1 week]`.
    ///
    /// **This is not the `TTL_INVALID` the checkout routes use.** The two
    /// checkout handlers emit `TTL_INVALID` (`check_out_license.rs:48`,
    /// `check_out_machine.rs:50`) while the artifact download emits
    /// `PRESIGN_TTL_INVALID` (`artifacts/service.rs:33`), so a handler written
    /// against one will silently not match the other. Different limits, too:
    /// checkout's ttl bounds a certificate's validity, this one bounds a URL's.
    ///
    /// The SDK checks the range before sending, so reaching this means the
    /// server's bounds have moved away from
    /// `TamgaClient.minimumDownloadTTLSeconds`/`maximumDownloadTTLSeconds`.
    public static let presignTTLInvalid = "PRESIGN_TTL_INVALID"

    /// A checkout route's `ttl` was out of range. See `presignTTLInvalid`,
    /// which is the artifact download's differently-spelled equivalent.
    public static let ttlInvalid = "TTL_INVALID"

    /// The deployment has no object-storage backend configured, so artifact
    /// bytes cannot be served. Not an authorization problem.
    public static let storageUnavailable = "STORAGE_UNAVAILABLE"

    // MARK: Uniqueness (HTTP 409)

    /// A machine with this fingerprint is already registered within the
    /// policy's `machine_uniqueness_strategy` scope, which may be another
    /// licence entirely.
    ///
    /// The uniqueness pre-check runs *before* the limit checks, so a
    /// re-activation of an already-registered fingerprint returns this rather
    /// than any of the limit codes above. That ordering is deliberate: the
    /// server means it as "already activated, carry on", not as a failure.
    /// `TamgaClient.reactivateMachine(_:scope:)` is the way to carry on.
    public static let fingerprintTaken = "FINGERPRINT_TAKEN"

    // MARK: Generic codes

    /// The addressed resource does not exist, or the credential cannot see it.
    ///
    /// Live, despite older SDK notes to the contrary: a heartbeat ping against a
    /// machine row that is genuinely gone surfaces here.
    ///
    /// **This -- not `HeartbeatStatus.dead` -- is the row-is-gone signal.** A
    /// machine reporting `DEAD` still holds its row and its seat and is revived
    /// by its next ping; a machine whose ping `404`s does not exist any more.
    /// See `TamgaError.isNotFound`.
    public static let notFound = "NOT_FOUND"

    /// No usable credential was presented.
    public static let unauthorized = "UNAUTHORIZED"

    /// The credential authenticated but is not permitted this action.
    ///
    /// A license-key credential always gets this from
    /// `TamgaClient.resetHeartbeat` and `TamgaClient.generateOfflineProof`.
    public static let forbidden = "FORBIDDEN"

    /// The server faulted. Says nothing about the licence.
    public static let internalServerError = "INTERNAL_SERVER_ERROR"

    // MARK: Limit normalization

    /// Create-time limit codes paired with the `ValidationCode` the validate
    /// endpoints report for the same condition.
    ///
    /// The two surfaces name the same limits differently, and which one a caller
    /// sees depends on the policy's overage strategy rather than on anything the
    /// caller did: under `NO_OVERAGE` the create is refused outright with one of
    /// these codes, while under `ALLOW_ACCESS` / `ALLOW_1_25X_OVERAGE` the create
    /// succeeds and the limit only surfaces at validate time. Normalizing lets a
    /// caller handle one vocabulary.
    public static let limitValidationCodes: [String: ValidationCode] = [
        machineLimitExceeded: .tooManyMachines,
        coreLimitExceeded: .tooManyCores,
        memoryLimitExceeded: .tooMuchMemory,
        diskLimitExceeded: .tooMuchDisk,
        tooManyProcesses: .tooManyProcesses
    ]

    /// The `ValidationCode` equivalent to a create-time limit code, or `nil` if
    /// `code` is not one.
    public static func limitValidationCode(for code: String) -> ValidationCode? {
        limitValidationCodes[code]
    }
}

// MARK: - Recognizing codes on a thrown error

extension TamgaError {
    /// Human-readable detail, when this is an `.api` error. Never match on it.
    public var apiDetail: String? {
        if case .api(let error) = self { return error.detail }
        return nil
    }

    /// The `ValidationCode` equivalent of a create-time policy-limit rejection,
    /// or `nil` when this error is not one.
    ///
    /// Lets a caller treat `422 MACHINE_LIMIT_EXCEEDED` from `createMachine` and
    /// `TOO_MANY_MACHINES` from `validateById` as the same condition, which they
    /// are -- only the policy's overage strategy decides which one arrives.
    public var limitValidationCode: ValidationCode? {
        guard case .api(let error) = self else { return nil }
        return TamgaAPIErrorCode.limitValidationCode(for: error.code)
    }

    /// This error rendered as an over-limit `ValidationMeta`, or `nil` when it is
    /// not a create-time limit rejection.
    ///
    /// `ts` is `nil`: a create-time rejection carries no validation timestamp,
    /// and inventing one would misreport when the server made its decision.
    public var overLimitMeta: ValidationMeta? {
        guard case .api(let error) = self,
              let code = TamgaAPIErrorCode.limitValidationCode(for: error.code)
        else {
            return nil
        }
        return ValidationMeta(ts: nil, valid: false, detail: error.detail, code: code)
    }

    /// Whether the server refused because a policy limit was exceeded, at either
    /// create time or validate time.
    public var isPolicyLimitExceeded: Bool { limitValidationCode != nil }

    /// Whether the licence itself was refused at the authentication gate --
    /// suspended, expired under `REVOKE_ACCESS`, or license-key auth disallowed
    /// by the policy.
    ///
    /// None of the three is retryable: each needs an operator or a policy change.
    public var isLicenseAuthenticationRejected: Bool {
        guard case .api(let error) = self else { return false }
        return error.code == TamgaAPIErrorCode.licenseSuspended
            || error.code == TamgaAPIErrorCode.licenseExpired
            || error.code == TamgaAPIErrorCode.licenseNotAllowed
    }

    /// Whether the server said the addressed resource does not exist.
    ///
    /// **This is the signal a heartbeat scheduler actually wants.** A machine
    /// reporting `HeartbeatStatus.dead` has not been culled -- culling is gated
    /// on the policy's `requireHeartbeat`, which is off by default -- so its row
    /// and its seat are still there and the next ping revives it. A `404` from
    /// the ping is different: the row is gone, and only a fresh activation
    /// brings the machine back.
    ///
    /// Matches the HTTP status as well as the code, so a `404` whose body was
    /// missing or unreadable -- which decodes to `APIError.unknownCode` -- is
    /// still recognized.
    public var isNotFound: Bool {
        guard case .api(let error) = self else { return false }
        return error.httpStatus == 404 || error.code == TamgaAPIErrorCode.notFound
    }

    /// Whether the server refused a machine create because the fingerprint is
    /// already registered within the policy's uniqueness scope.
    ///
    /// **This is a re-activation, not a limit and not a failure.** The server
    /// checks uniqueness *before* the quota limits precisely so that re-sending
    /// a known fingerprint says "already activated, carry on" rather than "buy
    /// another seat". `TamgaClient.reactivateMachine(_:scope:)` is the
    /// intended way out of it.
    ///
    /// Matched on the code alone. The status is `409`, but a `409` can also be
    /// `KEY_TAKEN` or `PID_TAKEN`, so status is not a substitute here the way
    /// it is for `isNotFound`.
    public var isFingerprintTaken: Bool {
        guard case .api(let error) = self else { return false }
        return error.code == TamgaAPIErrorCode.fingerprintTaken
    }
}
