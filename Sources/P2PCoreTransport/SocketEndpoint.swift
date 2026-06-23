// SocketEndpoint.swift
// Foundation-free (IP, port) pair identifying a datagram peer. Embedded-clean.

/// A datagram peer address: an ``IPAddress`` plus a UDP port.
///
/// This is the Foundation-free analogue of NIO's `SocketAddress`. Concrete
/// transports (M5) translate it to/from `sockaddr` at the syscall boundary.
public struct SocketEndpoint: Sendable, Hashable {
    /// The peer's IP address.
    public var address: IPAddress

    /// The peer's UDP port in host byte order.
    public var port: UInt16

    /// Creates an endpoint from an address and port.
    @inlinable
    public init(address: IPAddress, port: UInt16) {
        self.address = address
        self.port = port
    }

    /// Convenience initialiser for an IPv4 endpoint.
    @inlinable
    public init(v4 a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8, port: UInt16) {
        self.address = .v4(a, b, c, d)
        self.port = port
    }
}
