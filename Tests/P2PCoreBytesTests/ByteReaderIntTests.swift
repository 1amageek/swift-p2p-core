// ByteReaderIntTests.swift
// Big-endian fixed-width integer reads (incl. TLS UInt24) and truncation errors.

import Testing
@testable import P2PCoreBytes

@Suite("ByteReader integers")
struct ByteReaderIntTests {
    @Test func reader_readUInt8_bigEndian_knownVector() throws {
        var r = ByteReader([0x7F])
        #expect(try r.readUInt8() == 0x7F)
    }

    @Test func reader_readUInt16_bigEndian_knownVector() throws {
        var r = ByteReader([0x12, 0x34])
        #expect(try r.readUInt16() == 0x1234)
    }

    @Test func reader_readUInt24_zero_mid_max() throws {
        var zero = ByteReader([0x00, 0x00, 0x00])
        #expect(try zero.readUInt24() == 0x000000)
        var mid = ByteReader([0x12, 0x34, 0x56])
        #expect(try mid.readUInt24() == 0x123456)
        var max = ByteReader([0xFF, 0xFF, 0xFF])
        #expect(try max.readUInt24() == 0xFFFFFF)
    }

    @Test func reader_readUInt32_bigEndian_knownVector() throws {
        var r = ByteReader([0x12, 0x34, 0x56, 0x78])
        #expect(try r.readUInt32() == 0x12345678)
    }

    @Test func reader_readUInt64_bigEndian_knownVector() throws {
        var r = ByteReader([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        #expect(try r.readUInt64() == 0x0123456789ABCDEF)
    }

    @Test func reader_readUInt16_truncated_throwsInsufficientBytesExactCounts() {
        var r = ByteReader([0x01])
        #expect(throws: ByteError.insufficientBytes(requested: 2, available: 1)) {
            _ = try r.readUInt16()
        }
        // Cursor must not have advanced.
        #expect(r.position == 0)
    }

    @Test func reader_readUInt32_truncated_throwsInsufficientBytes() {
        var r = ByteReader([0x01, 0x02, 0x03])
        #expect(throws: ByteError.insufficientBytes(requested: 4, available: 3)) {
            _ = try r.readUInt32()
        }
    }

    @Test func reader_readUInt64_truncated_throwsInsufficientBytes() {
        var r = ByteReader([0x01, 0x02, 0x03, 0x04, 0x05])
        #expect(throws: ByteError.insufficientBytes(requested: 8, available: 5)) {
            _ = try r.readUInt64()
        }
    }
}
