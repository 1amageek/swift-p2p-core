// ByteWriterTests.swift
// Fixed-width writes (incl. UInt24), varint, length-prefixed vectors, span/bytes
// append, finalization, and the back-patched 3-byte length prefix.

import Testing
@testable import P2PCoreBytes

@Suite("ByteWriter")
struct ByteWriterTests {
    @Test func writer_writeUInt8_16_32_64_bigEndian() {
        var w = ByteWriter()
        w.writeUInt8(0x7F)
        w.writeUInt16(0x1234)
        w.writeUInt32(0x89ABCDEF)
        w.writeUInt64(0x0123456789ABCDEF)
        #expect(w.finishArray() == [
            0x7F,
            0x12, 0x34,
            0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ])
    }

    @Test func writer_writeUInt24_zero_mid_max() throws {
        var w = ByteWriter()
        try w.writeUInt24(0x000000)
        try w.writeUInt24(0x123456)
        try w.writeUInt24(0xFFFFFF)
        #expect(w.finishArray() == [
            0x00, 0x00, 0x00,
            0x12, 0x34, 0x56,
            0xFF, 0xFF, 0xFF,
        ])
    }

    @Test func writer_writeUInt24_overflow_throwsLengthOutOfRange() {
        var w = ByteWriter()
        #expect(throws: ByteError.lengthOutOfRange) {
            try w.writeUInt24(0x1000000)
        }
    }

    @Test func writer_writeVarint_allFourClasses_matchKnownVectors() throws {
        var w1 = ByteWriter(); try w1.writeVarint(63)
        #expect(w1.finishArray() == [0x3F])
        var w2 = ByteWriter(); try w2.writeVarint(16383)
        #expect(w2.finishArray() == [0x7F, 0xFF])
        var w4 = ByteWriter(); try w4.writeVarint(1_073_741_823)
        #expect(w4.finishArray() == [0xBF, 0xFF, 0xFF, 0xFF])
        var w8 = ByteWriter(); try w8.writeVarint((UInt64(1) << 62) - 1)
        #expect(w8.finishArray() == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }

    @Test func writer_writeVarint_overMax_throwsInvalidVarint() {
        var w = ByteWriter()
        #expect(throws: ByteError.invalidVarint) {
            try w.writeVarint(UInt64(1) << 62)
        }
    }

    @Test func writer_writeVector8_16_24_32_prependsLength() throws {
        var w8 = ByteWriter(); try w8.writeVector8([1, 2, 3])
        #expect(w8.finishArray() == [0x03, 1, 2, 3])
        var w16 = ByteWriter(); try w16.writeVector16([1, 2])
        #expect(w16.finishArray() == [0x00, 0x02, 1, 2])
        var w24 = ByteWriter(); try w24.writeVector24([9])
        #expect(w24.finishArray() == [0x00, 0x00, 0x01, 9])
        var w32 = ByteWriter(); try w32.writeVector32([7, 8])
        #expect(w32.finishArray() == [0x00, 0x00, 0x00, 0x02, 7, 8])
    }

    @Test func writer_writeVector8_oversized_throwsLengthOutOfRange() {
        var w = ByteWriter()
        let payload = [UInt8](repeating: 0, count: 257)
        #expect(throws: ByteError.lengthOutOfRange) {
            try w.writeVector8(payload)
        }
    }

    @Test func writer_writeVector16_oversized_throwsLengthOutOfRange() {
        var w = ByteWriter()
        let payload = [UInt8](repeating: 0, count: 0x10000)
        #expect(throws: ByteError.lengthOutOfRange) {
            try w.writeVector16(payload)
        }
    }

    @Test func writer_writeVector24_oversized_throwsLengthOutOfRange() {
        var w = ByteWriter()
        let payload = [UInt8](repeating: 0, count: 0x1000000)
        #expect(throws: ByteError.lengthOutOfRange) {
            try w.writeVector24(payload)
        }
    }

    @Test func writer_writeVarintVector_roundTrip() throws {
        var w = ByteWriter()
        let payload = [UInt8](repeating: 0x33, count: 64)
        try w.writeVarintVector(payload)
        var r = ByteReader(w.finishArray())
        #expect(try r.readVarintVector() == payload)
    }

    @Test func writer_writeSpan_appendsBorrowedView() {
        var w = ByteWriter()
        let source: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        w.writeSpan(source.span)
        #expect(w.finishArray() == source)
    }

    @Test func writer_writeBytes_appendsBytesValue() {
        var w = ByteWriter()
        w.writeBytes(Bytes([1, 2, 3]))
        #expect(w.finishArray() == [1, 2, 3])
    }

    @Test func writer_finish_returnsBytes_finishArray_returnsArray() {
        var w = ByteWriter()
        w.writeUInt8(0xAB)
        #expect(w.finish().toArray() == [0xAB])
        #expect(w.finishArray() == [0xAB])
    }

    @Test func writer_lengthPrefixed24_patchesBodyLength() throws {
        var w = ByteWriter()
        try w.writeLengthPrefixed24 { (inner: inout ByteWriter) throws(ByteError) in
            inner.writeUInt8(0xAA)
            inner.writeUInt8(0xBB)
            inner.writeUInt8(0xCC)
        }
        // 3-byte length 0x000003 then the body.
        #expect(w.finishArray() == [0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC])
    }

    @Test func writer_lengthPrefixed24_nested_patchesEachLevel() throws {
        var w = ByteWriter()
        try w.writeLengthPrefixed24 { (outer: inout ByteWriter) throws(ByteError) in
            try outer.writeLengthPrefixed24 { (inner: inout ByteWriter) throws(ByteError) in
                inner.writeUInt8(0x01)
                inner.writeUInt8(0x02)
            }
        }
        // Outer length = 5 (3-byte inner prefix + 2 body); inner length = 2.
        #expect(w.finishArray() == [0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x01, 0x02])
    }

    @Test func writer_lengthPrefixed24_bodyOverflow_throwsLengthOutOfRange() {
        var w = ByteWriter()
        #expect(throws: ByteError.lengthOutOfRange) {
            try w.writeLengthPrefixed24 { (inner: inout ByteWriter) throws(ByteError) in
                inner.writeBytes([UInt8](repeating: 0, count: 0x1000000))
            }
        }
    }
}
