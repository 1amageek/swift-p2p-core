// ByteReaderVectorTests.swift
// Length-prefixed vector reads (TLS u8/u16/u24, u32, QUIC varint) and overflow.

import Testing
@testable import P2PCoreBytes

@Suite("ByteReader vectors")
struct ByteReaderVectorTests {
    @Test func vector8_roundTrip() throws {
        var w = ByteWriter()
        try w.writeVector8([0xAA, 0xBB, 0xCC])
        var r = ByteReader(w.finishArray())
        #expect(try r.readVector8() == [0xAA, 0xBB, 0xCC])
        #expect(r.isAtEnd == true)
    }

    @Test func vector16_roundTrip() throws {
        let payload = [UInt8](repeating: 0x5A, count: 300)
        var w = ByteWriter()
        try w.writeVector16(payload)
        var r = ByteReader(w.finishArray())
        #expect(try r.readVector16() == payload)
    }

    @Test func vector24_roundTrip() throws {
        let payload = [UInt8](repeating: 0x7E, count: 70_000)
        var w = ByteWriter()
        try w.writeVector24(payload)
        var r = ByteReader(w.finishArray())
        #expect(try r.readVector24() == payload)
    }

    @Test func vector32_roundTrip() throws {
        let payload: [UInt8] = [1, 2, 3, 4, 5]
        var w = ByteWriter()
        try w.writeVector32(payload)
        var r = ByteReader(w.finishArray())
        #expect(try r.readVector32() == payload)
    }

    @Test func varintVector_roundTrip() throws {
        let payload = [UInt8](repeating: 0x11, count: 200)
        var w = ByteWriter()
        try w.writeVarintVector(payload)
        var r = ByteReader(w.finishArray())
        #expect(try r.readVarintVector() == payload)
    }

    @Test func vector16_declaredLengthExceedsRemaining_throwsLengthOverflowOrInsufficient() {
        // Declares 0x0005 but supplies only two payload bytes.
        var r = ByteReader([0x00, 0x05, 0x01, 0x02])
        var threwExpected = false
        do {
            _ = try r.readVector16()
        } catch {
            switch error {
            case .lengthOverflow, .insufficientBytes:
                threwExpected = true
            default:
                threwExpected = false
            }
        }
        #expect(threwExpected)
    }

    @Test func vector8_atEnd_throwsInsufficientBytes() {
        var r = ByteReader([])
        #expect(throws: ByteError.insufficientBytes(requested: 1, available: 0)) {
            _ = try r.readVector8()
        }
    }
}
