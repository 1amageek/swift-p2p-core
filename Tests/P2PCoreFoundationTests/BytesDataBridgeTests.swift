// BytesDataBridgeTests.swift
// Data <-> Bytes bridge round-trips and fidelity.

import Testing
import Foundation
@testable import P2PCoreFoundation
import P2PCoreBytes

@Suite("Bytes <-> Data bridge")
struct BytesDataBridgeTests {
    @Test func dataToBytesToData_roundTrip_equal() {
        let data = Data([1, 2, 3, 4, 5])
        let bytes = Bytes(data)
        #expect(bytes.data == data)
    }

    @Test func bytesToDataToBytes_roundTrip_equal() {
        let bytes = Bytes([10, 20, 30])
        let data = bytes.data
        #expect(Bytes(data).toArray() == bytes.toArray())
    }

    @Test func emptyData_bridges_toEmptyBytes() {
        let empty = Data()
        let bytes = Bytes(empty)
        #expect(bytes.isEmpty)
        #expect(bytes.data.isEmpty)
    }

    @Test func largeBuffer_bridges_faithfully() {
        var source = [UInt8]()
        source.reserveCapacity(64 * 1024)
        for i in 0..<(64 * 1024) { source.append(UInt8(truncatingIfNeeded: i)) }
        let data = Data(source)
        let bytes = Bytes(data)
        #expect(bytes.count == 64 * 1024)
        #expect(bytes.toArray() == source)
        #expect(bytes.data == data)
    }

    @Test func data_coreBytes_matches_BytesInitData() {
        let data = Data([0xDE, 0xAD, 0xBE, 0xEF])
        #expect(data.coreBytes.toArray() == Bytes(data).toArray())
    }
}
