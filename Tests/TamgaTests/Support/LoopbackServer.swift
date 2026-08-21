import Foundation

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// A minimal loopback HTTP/1.1 server for exercising the real `URLSession`
/// path.
///
/// Most of the suite runs through `MockPerformer`, which is the right seam for
/// endpoint behaviour. But two controls live in the `URLSession` layer that a
/// mock cannot reach: refusing redirects, and cancelling an oversized body
/// mid-transfer. Both are security boundaries, so they get covered against a
/// real socket rather than assumed.
///
/// Raw POSIX sockets rather than a framework, so it behaves the same on macOS
/// and Linux. It serves one canned response per connection and shuts down after.
final class LoopbackServer: @unchecked Sendable {
    /// What to answer with.
    enum Behaviour: Sendable {
        /// A `3xx` pointing at `location`, which a correct client refuses.
        ///
        /// The status is a parameter because `302` and `303` are not
        /// interchangeable to `URLSession`: a `303` rewrites the follow-up to
        /// `GET`, and the artifact download route answers exactly `303`.
        case redirect(status: Int, reason: String, to: String)
        /// A 200 declaring `declaredLength` and then writing `actualBytes`
        /// bytes. Declaring more than is sent is how the streaming cap gets
        /// exercised without waiting on a real multi-megabyte transfer.
        case body(declaredLength: Int, actualBytes: Int)
    }

    private let listenSocket: Int32
    private let queue = DispatchQueue(label: "tamga.loopback")
    private let counterLock = NSLock()
    private var accepted = 0
    private(set) var port: UInt16 = 0

    /// How many connections this server has accepted.
    ///
    /// Zero is the assertion that matters for a redirect target: a client that
    /// refused the hop never opened a socket to it, so no header of any kind
    /// reached it.
    var acceptedConnections: Int {
        counterLock.lock()
        defer { counterLock.unlock() }
        return accepted
    }

    init?(behaviour: Behaviour) {
        // Glibc types SOCK_STREAM as `__socket_type`; Darwin types it as Int32.
        #if canImport(Glibc)
        let streamType = Int32(SOCK_STREAM.rawValue)
        #else
        let streamType = SOCK_STREAM
        #endif
        listenSocket = socket(AF_INET, streamType, 0)
        guard listenSocket >= 0 else { return nil }

        var reuse: Int32 = 1
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listenSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(listenSocket, 4) == 0 else {
            close(listenSocket)
            return nil
        }

        var boundAddress = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(listenSocket, $0, &length)
            }
        }
        guard named == 0 else {
            close(listenSocket)
            return nil
        }
        port = UInt16(bigEndian: boundAddress.sin_port)

        queue.async { [listenSocket, weak self] in
            let connection = accept(listenSocket, nil, nil)
            guard connection >= 0 else { return }
            if let self {
                self.counterLock.lock()
                self.accepted += 1
                self.counterLock.unlock()
            }
            var scratch = [UInt8](repeating: 0, count: 4096)
            _ = read(connection, &scratch, 4096)
            Self.respond(on: connection, behaviour: behaviour)
            close(connection)
        }
    }

    private static func respond(on connection: Int32, behaviour: Behaviour) {
        switch behaviour {
        case .redirect(let status, let reason, let location):
            let response = "HTTP/1.1 \(status) \(reason)\r\nLocation: \(location)\r\n"
                + "Content-Length: 0\r\nConnection: close\r\n\r\n"
            _ = response.withCString { write(connection, $0, strlen($0)) }
        case .body(let declaredLength, let actualBytes):
            let header = "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.api+json\r\n"
                + "Content-Length: \(declaredLength)\r\nConnection: close\r\n\r\n"
            _ = header.withCString { write(connection, $0, strlen($0)) }
            var remaining = actualBytes
            let chunk = [UInt8](repeating: UInt8(ascii: "x"), count: max(1, min(actualBytes, 16384)))
            while remaining > 0 {
                let count = min(remaining, chunk.count)
                let written = chunk.withUnsafeBytes { write(connection, $0.baseAddress, count) }
                if written <= 0 { break }
                remaining -= written
            }
        }
    }

    var baseURL: String { "http://127.0.0.1:\(port)" }

    func stop() {
        close(listenSocket)
    }
}
