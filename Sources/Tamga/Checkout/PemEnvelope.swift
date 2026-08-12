import Foundation

/// Shared PEM-envelope stripping for `LicenseFile` and `MachineFile`.
enum PemEnvelope {
    static func strip(_ pem: String, beginMarker: String, endMarker: String) throws -> String {
        let trimmed = pem.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(beginMarker) else {
            throw TamgaCheckoutError.offlineFileFormat("Missing '\(beginMarker)' marker.")
        }
        guard trimmed.hasSuffix(endMarker) else {
            throw TamgaCheckoutError.offlineFileFormat("Missing '\(endMarker)' marker.")
        }

        // SECURITY: hasPrefix/hasSuffix only guarantee the trimmed string is
        // at least as long as each marker individually -- a short,
        // attacker-crafted string can satisfy both independently while being
        // shorter than beginMarker.count + endMarker.count (the two markers
        // "overlap"). Without this guard the slice below computes a negative
        // range and traps instead of throwing the documented
        // TamgaCheckoutError.offlineFileFormat, breaking callers that only
        // catch that case for untrusted .lic/.machine input. Same class of
        // bug as a HIGH finding already fixed in tamga-dotnet's equivalent
        // PemEnvelope.Strip during that repo's mandatory security review.
        guard trimmed.count >= beginMarker.count + endMarker.count else {
            throw TamgaCheckoutError.offlineFileFormat(
                "Body between '\(beginMarker)' and '\(endMarker)' is malformed or too short."
            )
        }

        let bodyStart = trimmed.index(trimmed.startIndex, offsetBy: beginMarker.count)
        let bodyEnd = trimmed.index(trimmed.endIndex, offsetBy: -endMarker.count)
        let body = trimmed[bodyStart..<bodyEnd]
        return body.filter { !$0.isWhitespace }
    }
}
