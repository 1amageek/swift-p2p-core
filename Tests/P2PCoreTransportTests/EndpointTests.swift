// EndpointTests.swift
// Foundation-free endpoint value types: IPv4/IPv6, SocketEndpoint, InlineIPv6.

import Testing
@testable import P2PCoreTransport

@Suite("Transport endpoints")
struct EndpointTests {
    @Test func ipv4_rawBytes_lengthFour() {
        let addr = IPAddress.v4(192, 168, 1, 10)
        #expect(addr.rawBytes == [192, 168, 1, 10])
        #expect(addr.rawBytes.count == 4)
    }

    @Test func ipv6_rawBytes_lengthSixteen() {
        let octets = InlineIPv6(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        let addr = IPAddress.v6(octets)
        #expect(addr.rawBytes.count == 16)
        #expect(addr.rawBytes == [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    @Test func ipAddress_isIPv4_discriminates() {
        #expect(IPAddress.v4(1, 2, 3, 4).isIPv4)
        let octets = InlineIPv6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        #expect(!IPAddress.v6(octets).isIPv4)
    }

    @Test func socketEndpoint_v4Convenience_init() {
        let endpoint = SocketEndpoint(v4: 10, 0, 0, 1, port: 4433)
        #expect(endpoint.port == 4433)
        #expect(endpoint.address == .v4(10, 0, 0, 1))
    }

    @Test func socketEndpoint_equatable_hashable() {
        let a = SocketEndpoint(v4: 1, 2, 3, 4, port: 80)
        let b = SocketEndpoint(v4: 1, 2, 3, 4, port: 80)
        let c = SocketEndpoint(v4: 1, 2, 3, 4, port: 81)
        #expect(a == b)
        #expect(a != c)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func inlineIPv6_toArray_orderPreserved() {
        let octets = InlineIPv6(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        #expect(octets.toArray() == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    }
}
