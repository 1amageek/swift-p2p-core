// ByteReaderVarintTests.swift
// QUIC variable-length integer decode (RFC 9000 §16) across all four classes,
// plus truncation and the non-consuming length lookahead.

import Testing
@testable import P2PCoreBytes

@Suite("ByteReader varint")
struct ByteReaderVarintTests {
    @Test func varint_decode_oneByteClass_boundary_63_64() throws {
        // 63 fits in one byte (0x3F); 64 needs the two-byte class (0x40 0x40).
        var r63 = ByteReader([0x3F])
        #expect(try r63.readVarint() == 63)
        var r64 = ByteReader([0x40, 0x40])
        #expect(try r64.readVarint() == 64)
    }

    @Test func varint_decode_twoByteClass_boundary_16383_16384() throws {
        // 16383 = 0x3FFF in two-byte class: 0x7F 0xFF.
        var r16383 = ByteReader([0x7F, 0xFF])
        #expect(try r16383.readVarint() == 16383)
        // 16384 needs the four-byte class: 0x80 0x00 0x40 0x00.
        var r16384 = ByteReader([0x80, 0x00, 0x40, 0x00])
        #expect(try r16384.readVarint() == 16384)
    }

    @Test func varint_decode_fourByteClass_boundary_1073741823_and_above() throws {
        // 1073741823 = 0x3FFFFFFF in four-byte class: 0xBF 0xFF 0xFF 0xFF.
        var rMax4 = ByteReader([0xBF, 0xFF, 0xFF, 0xFF])
        #expect(try rMax4.readVarint() == 1_073_741_823)
        // 1073741824 needs the eight-byte class: 0xC0 ... 0x40000000.
        var rOver = ByteReader([0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00])
        #expect(try rOver.readVarint() == 1_073_741_824)
    }

    @Test func varint_decode_eightByteClass_boundary_2pow62minus1() throws {
        // 2^62 - 1 = 0x3FFFFFFFFFFFFFFF: 0xFF .. 0xFF (eight 0xFF bytes).
        var r = ByteReader([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        #expect(try r.readVarint() == (UInt64(1) << 62) - 1)
    }

    @Test func varint_decode_truncated_throwsInsufficientBytes() {
        // Declares the four-byte class but only supplies two bytes.
        var r = ByteReader([0x80, 0x00])
        #expect(throws: ByteError.insufficientBytes(requested: 3, available: 1)) {
            _ = try r.readVarint()
        }
    }

    @Test func peekVarintLength_returnsEncodedWidth_withoutAdvancing() {
        let r1 = ByteReader([0x3F])
        #expect(r1.peekVarintLength() == 1)
        #expect(r1.position == 0)
        let r2 = ByteReader([0x40, 0x40])
        #expect(r2.peekVarintLength() == 2)
        let r4 = ByteReader([0x80, 0, 0, 0])
        #expect(r4.peekVarintLength() == 4)
        let r8 = ByteReader([0xC0, 0, 0, 0, 0, 0, 0, 0])
        #expect(r8.peekVarintLength() == 8)
    }

    @Test func peekVarintLength_atEnd_returnsNil() {
        let r = ByteReader([])
        #expect(r.peekVarintLength() == nil)
    }
}
