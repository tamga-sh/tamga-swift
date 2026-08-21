import Foundation

/// `Errors.swift`
///
/// Two error families, deliberately distinct:
///
/// - `TamgaError` below covers live API calls made through `TamgaClient`.
/// - `TamgaCheckoutError` further down covers parsing, verifying and
///   decrypting an already-issued offline file or proof, which needs no
///   network at all.
///
/// A caller deciding whether to fall back to offline verification wants that
/// distinction, and within `TamgaError` wants the further distinction between
/// `.transport` (no response arrived, which says nothing about the license) and
/// `.api` (the server answered, and its answer is authoritative).

/// An error from a live API call.
public enum TamgaError: Error, Sendable {
    /// The server returned a non-2xx response.
    ///
    /// Match on `error.code`, which is stable and server-documented. Never
    /// match on `detail`, which is human-readable text that may be reworded
    /// between server versions.
    case api(APIError)

    /// The request never produced an HTTP response -- a connection failure, a
    /// timeout, a TLS error, or a cancelled retry backoff.
    ///
    /// This says nothing about the license itself, unlike `.api`.
    case transport(message: String, underlying: (any Error)?)

    /// The server answered with something this SDK could not decode as either
    /// a valid response or a JSON:API error document.
    ///
    /// `underlying` keeps the original typed `DecodingError`, whose coding path
    /// says which field failed. Stringifying it here would leave a caller's
    /// error reporting nothing structured to work with.
    case malformedResponse(message: String, underlying: (any Error)?)

    /// An activation found the license over a policy limit.
    ///
    /// **Whether the machine still exists depends on which call threw, and the
    /// rule is "roll back only what this call created".**
    ///
    /// - `TamgaClient.activateMachine` created the machine, so it deletes it
    ///   before throwing -- a rejected activation must not leave an orphaned
    ///   row consuming a seat. The exception is a create-time `422` limit
    ///   rejection, where the server refused before writing a row and there is
    ///   nothing to roll back.
    /// - `TamgaClient.reactivateMachine` may instead have adopted a machine
    ///   that already existed. **That one is never deleted**: it predates the
    ///   call, and surrendering a seat the caller never offered up is not a
    ///   rollback.
    ///
    /// The meta identifies which limit was hit either way.
    case machineOverLimit(ValidationMeta)

    /// `TamgaClient.activateMachine` created the machine, then the validation
    /// call itself failed -- a network error or an unrelated server fault, not
    /// a verdict about the license.
    ///
    /// **The machine still exists.** Whether it is permitted is unknown, so
    /// deleting it would destroy a seat on the strength of a transient error.
    /// The machine is handed back instead: retry the validation, or delete it
    /// with `deleteMachine(_:)`.
    ///
    /// This mirrors `tamga-go`, which returns the created machine alongside the
    /// error rather than rolling back. `tamga-java` rolls back instead, because
    /// throwing leaves it no way to return the machine; Swift has one.
    case activationValidationFailed(machine: Machine, underlying: any Error)

    /// A decoded JSON:API error object plus the response it arrived with.
    public struct APIError: Equatable, Sendable {
        /// The code used when the body is absent, unreadable, or not JSON:API.
        public static let unknownCode = "UNKNOWN"

        /// The stable error code. This is what callers should match on.
        public let code: String
        /// The HTTP status the error arrived with.
        public let httpStatus: Int
        /// Human-readable detail. Never match on this.
        public let detail: String?
        /// The short error title.
        public let title: String?
        /// The server-assigned error id.
        public let id: String?
        /// A JSON pointer identifying the offending request field.
        public let pointer: String?
        /// Diagnostic response headers, notably the request id worth logging.
        public let responseMetadata: ResponseMetadata
    }

    /// The stable error code, when this is an `.api` error.
    public var apiCode: String? {
        if case .api(let error) = self { return error.code }
        return nil
    }

    /// The HTTP status, when this is an `.api` error.
    public var httpStatus: Int? {
        if case .api(let error) = self { return error.httpStatus }
        return nil
    }
}

extension TamgaError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .api(let error):
            if let detail = error.detail {
                return "\(error.code): \(detail)"
            }
            return error.code
        case .transport(let message, _):
            return message
        case .malformedResponse(let message, _):
            return message
        case .machineOverLimit(let meta):
            return "Machine activation rolled back: over policy limit (\(meta.code.wireValue))."
        case .activationValidationFailed(let machine, let underlying):
            return "Machine \(machine.id) was created, but validating the license failed: "
                + "\(underlying). The machine still exists."
        }
    }
}

/// The wire shape of a JSON:API error document.
struct ErrorDocument: Decodable {
    struct Source: Decodable {
        let pointer: String?
    }

    struct Entry: Decodable {
        let id: String?
        let status: String?
        let code: String?
        let title: String?
        let detail: String?
        let source: Source?
    }

    let errors: [Entry]?
}

/// Errors thrown by `Checkout/LicenseFile.swift`, `Checkout/MachineFile.swift`,
/// and `Proof.swift`. Distinct from the (still-deferred) HTTP-facing
/// `TamgaError` above -- these describe failures in parsing/verifying/
/// decrypting an already-issued offline file or proof, not a live API call.
public enum TamgaCheckoutError: Error, Equatable {
    /// The PEM envelope or inner JSON is malformed.
    case offlineFileFormat(String)
    /// Signature verification failed -- the file may be forged or corrupted.
    case signatureVerificationFailed
    /// Decryption failed AFTER a successful signature check -- almost always
    /// the wrong license key (license files) or the wrong license
    /// key/fingerprint pair (machine files), occasionally payload
    /// corruption. Kept distinct from `signatureVerificationFailed` so a
    /// caller can react differently ("check your license key" vs. "this
    /// file may be forged/tampered") -- unlike a network-facing oracle,
    /// there's no adversary benefit to collapsing the two for a file the
    /// user already has in hand.
    case decryptionFailed(String)
    /// The certificate's `alg` field, or a caller-supplied scheme, isn't
    /// recognized.
    case unsupportedAlgorithm(String)
    /// The file's signature verified, but its signed `exp` claim has passed --
    /// an authentic license file that has simply run out.
    ///
    /// Its own case on purpose: a caller that cannot tell "expired" from
    /// "forged" either warns the user about tampering when their trial merely
    /// ended, or treats a forgery as a renewal prompt. The associated value is
    /// the `exp` claim, seconds since the Unix epoch.
    case expired(Int64)
    /// `RSA_2048_JWT_RS256` (or any other scheme never implemented for a
    /// given file type) was requested explicitly.
    case schemeNotSupported(String)
    /// Client-side mirror of the server's `422 TTL_INVALID`: `ttl` must be
    /// `> 0 && <= 31536000` (365 days).
    case ttlInvalid(String)
}

extension TamgaCheckoutError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .offlineFileFormat(let message):
            return message
        case .signatureVerificationFailed:
            return "Signature verification failed -- the file may be forged or corrupted."
        case .decryptionFailed(let message):
            return message
        case .unsupportedAlgorithm(let message):
            return message
        case .expired(let exp):
            return "License file expired at unix timestamp \(exp)."
        case .schemeNotSupported(let message):
            return message
        case .ttlInvalid(let message):
            return message
        }
    }
}
