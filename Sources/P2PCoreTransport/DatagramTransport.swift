// DatagramTransport.swift
// Connectionless datagram I/O seam. Inverts the NIO dependency so QUIC uses UDP
// through this protocol. Embedded-clean: no NIO, no Foundation, no `any`.

import _Concurrency   // REQUIRED under Embedded for AsyncSequence/async (probe P10)

/// A connectionless (UDP-style) datagram transport.
///
/// This is the single seam through which the QUIC layer performs UDP I/O,
/// replacing direct NIO usage. Concrete implementations (a NIO-backed one and a
/// raw-POSIX one) arrive in M5; this milestone defines the contract only.
///
/// The inbound side is exposed as an `associatedtype Incoming: AsyncSequence`
/// rather than a concrete `AsyncStream`, so an Embedded implementation can
/// supply whatever async sequence it can build, while the generic upper layer
/// (`<T: DatagramTransport>`) stays free of `any` existentials.
public protocol DatagramTransport: Sendable {
    /// The async sequence type yielding inbound datagrams.
    associatedtype Incoming: AsyncSequence where Incoming.Element == Datagram

    /// The largest payload (in bytes) `send` will accept.
    var maximumDatagramSize: Int { get }

    /// Sends `payload` to `endpoint`.
    ///
    /// - Parameters:
    ///   - payload: The bytes to send (borrowed; not retained past the call).
    ///   - endpoint: The destination peer.
    /// - Throws:
    ///   - ``TransportError/closed`` if the transport is closed.
    ///   - ``TransportError/messageTooLarge(size:maximum:)`` if `payload` exceeds
    ///     ``maximumDatagramSize``.
    ///   - ``TransportError/unsupportedPlatform(_:)`` if the requested backend is
    ///     not available on this platform.
    ///   - ``TransportError/ioFailure`` on a backend error.
    func send(_ payload: Span<UInt8>, to endpoint: SocketEndpoint) async throws(TransportError)

    /// The stream of inbound datagrams.
    ///
    /// Iteration finishes when the transport is closed.
    var incoming: Incoming { get }

    /// Closes the transport, releasing its socket and terminating ``incoming``.
    func close() async
}
