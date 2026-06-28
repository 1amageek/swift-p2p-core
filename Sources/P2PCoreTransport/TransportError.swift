// TransportError.swift
// Typed errors for the datagram transport seam. Embedded-clean.

/// Errors raised by a ``DatagramTransport``.
///
/// Concrete transports (M5) map their backend/syscall errors onto these cases so
/// callers depend only on the abstraction.
public enum TransportError: Error, Equatable, Sendable {
    /// The transport has been closed and can no longer send or receive.
    case closed

    /// A datagram exceeded the maximum size the transport can send.
    ///
    /// - Parameters:
    ///   - size: The attempted payload size.
    ///   - maximum: The transport's maximum datagram size.
    case messageTooLarge(size: Int, maximum: Int)

    /// The destination endpoint is malformed or unreachable.
    case invalidEndpoint

    /// The requested transport capability is not available on this platform.
    ///
    /// This is distinct from ``ioFailure``: callers can treat it as a static
    /// capability mismatch rather than a transient send/receive failure.
    case unsupportedPlatform(String)

    /// A send or receive failed at the backend/syscall level.
    case ioFailure
}
