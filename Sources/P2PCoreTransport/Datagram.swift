// Datagram.swift
// An inbound datagram: payload bytes plus the source endpoint. Embedded-clean.

/// A received datagram: its payload and the peer it came from.
///
/// Payload is an owned `[UInt8]` (not Foundation `Data`); the source is a
/// Foundation-free ``SocketEndpoint``.
public struct Datagram: Sendable {
    /// The datagram payload bytes.
    public var payload: [UInt8]

    /// The peer endpoint the datagram originated from.
    public var source: SocketEndpoint

    /// Creates a datagram from a payload and source endpoint.
    @inlinable
    public init(payload: [UInt8], source: SocketEndpoint) {
        self.payload = payload
        self.source = source
    }
}
