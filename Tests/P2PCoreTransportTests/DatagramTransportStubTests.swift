// DatagramTransportStubTests.swift
// Proves DatagramTransport is conformable with a custom AsyncSequence and no
// `any` (A10), that the generic `for try await` consumer works and terminates
// (N2), and that send enforces its size/closed contract.

import Testing
import Foundation  // NSLock only; the transport API itself stays Foundation-free.
@testable import P2PCoreTransport

// MARK: - A conforming stub with a finite custom AsyncSequence

/// A finite async sequence of datagrams (drains a fixed list, then ends).
struct StubIncoming: AsyncSequence {
    typealias Element = Datagram
    let datagrams: [Datagram]

    func makeAsyncIterator() -> Iterator {
        Iterator(datagrams: datagrams)
    }

    struct Iterator: AsyncIteratorProtocol {
        let datagrams: [Datagram]
        var index = 0
        mutating func next() async -> Datagram? {
            guard index < datagrams.count else { return nil }  // nil at end → loop terminates
            defer { index += 1 }
            return datagrams[index]
        }
    }
}

/// An in-memory transport recording sends and replaying a fixed inbound list.
/// State is guarded by a `Mutex` so the type is `Sendable` without `any`.
final class StubTransport: DatagramTransport {
    typealias Incoming = StubIncoming

    let maximumDatagramSize = 1200
    private let inbound: [Datagram]
    private let state = StubState()

    init(inbound: [Datagram]) {
        self.inbound = inbound
    }

    var sentCount: Int { state.sentCount }
    func lastSent() -> (payload: [UInt8], to: SocketEndpoint)? { state.last() }

    func send(_ payload: Span<UInt8>, to endpoint: SocketEndpoint) async throws(TransportError) {
        guard !state.isClosed else { throw TransportError.closed }
        guard payload.count <= maximumDatagramSize else {
            throw TransportError.messageTooLarge(size: payload.count, maximum: maximumDatagramSize)
        }
        var copy = [UInt8]()
        copy.reserveCapacity(payload.count)
        for i in 0..<payload.count { copy.append(payload[i]) }
        state.record(payload: copy, to: endpoint)
    }

    var incoming: StubIncoming {
        StubIncoming(datagrams: state.isClosed ? [] : inbound)
    }

    func close() async {
        state.close()
    }
}

/// Thread-safe state for the stub transport.
final class StubState: @unchecked Sendable {
    private let lock = NSLock()
    private var sent: [(payload: [UInt8], to: SocketEndpoint)] = []
    private var closed = false

    var sentCount: Int { lock.withLock { sent.count } }
    var isClosed: Bool { lock.withLock { closed } }
    func record(payload: [UInt8], to endpoint: SocketEndpoint) {
        lock.withLock { sent.append((payload, endpoint)) }
    }
    func last() -> (payload: [UInt8], to: SocketEndpoint)? {
        lock.withLock { sent.last }
    }
    func close() { lock.withLock { closed = true } }
}

// MARK: - Generic consumer (lives in *Core engines in production; here for the test)

/// `for try await` is mandatory: AsyncSequence.Failure is erased through the
/// generic, so `for await` would not compile (N2). The function carries `throws`.
func collect<T: DatagramTransport>(_ transport: T, limit: Int) async throws -> [[UInt8]] {
    var received: [[UInt8]] = []
    for try await dg in transport.incoming {
        received.append(dg.payload)
        if received.count >= limit { break }
    }
    return received
}

@Suite("DatagramTransport stub")
struct DatagramTransportStubTests {
    @Test func stubTransport_conformsToDatagramTransport_noAny() async throws {
        let transport = StubTransport(inbound: [])
        #expect(transport.maximumDatagramSize == 1200)
    }

    @Test func genericConsumer_forTryAwait_yieldsDatagramsInOrder() async throws {
        let dgs = [
            Datagram(payload: [1], source: SocketEndpoint(v4: 1, 0, 0, 1, port: 10)),
            Datagram(payload: [2], source: SocketEndpoint(v4: 1, 0, 0, 2, port: 20)),
            Datagram(payload: [3], source: SocketEndpoint(v4: 1, 0, 0, 3, port: 30)),
        ]
        let transport = StubTransport(inbound: dgs)
        let received = try await collect(transport, limit: 10)
        #expect(received == [[1], [2], [3]])
    }

    @Test(.timeLimit(.minutes(1)))
    func genericConsumer_terminatesAfterClose_noHang() async throws {
        let dgs = [Datagram(payload: [1], source: SocketEndpoint(v4: 1, 0, 0, 1, port: 10))]
        let transport = StubTransport(inbound: dgs)
        await transport.close()
        // After close(), incoming yields nothing and the loop terminates promptly.
        let received = try await collect(transport, limit: 10)
        #expect(received.isEmpty)
    }

    @Test func send_oversizedPayload_throwsMessageTooLarge() async {
        let transport = StubTransport(inbound: [])
        let big = [UInt8](repeating: 0, count: 2000)
        await #expect(throws: TransportError.messageTooLarge(size: 2000, maximum: 1200)) {
            try await transport.send(big.span, to: SocketEndpoint(v4: 1, 1, 1, 1, port: 1))
        }
    }

    @Test func send_afterClose_throwsClosed() async {
        let transport = StubTransport(inbound: [])
        await transport.close()
        let payload: [UInt8] = [1, 2, 3]
        await #expect(throws: TransportError.closed) {
            try await transport.send(payload.span, to: SocketEndpoint(v4: 1, 1, 1, 1, port: 1))
        }
    }

    @Test func send_withinLimit_succeeds() async throws {
        let transport = StubTransport(inbound: [])
        let payload: [UInt8] = [9, 9, 9]
        try await transport.send(payload.span, to: SocketEndpoint(v4: 1, 1, 1, 1, port: 53))
        #expect(transport.sentCount == 1)
        #expect(transport.lastSent()?.payload == [9, 9, 9])
        #expect(transport.lastSent()?.to.port == 53)
    }
}
