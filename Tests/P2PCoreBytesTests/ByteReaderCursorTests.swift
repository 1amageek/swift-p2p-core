// ByteReaderCursorTests.swift
// Cursor invariants, skip/readBytes/readRemaining, subReader, remainingSpan, peek.

import Testing
@testable import P2PCoreBytes

@Suite("ByteReader cursor")
struct ByteReaderCursorTests {
    @Test func reader_positionPlusRemaining_equalsCount_afterEveryRead() throws {
        var r = ByteReader([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        #expect(r.position + r.remaining == r.count)
        _ = try r.readUInt8()
        #expect(r.position + r.remaining == r.count)
        _ = try r.readUInt16()
        #expect(r.position + r.remaining == r.count)
        _ = try r.readUInt32()
        #expect(r.position + r.remaining == r.count)
    }

    @Test func reader_isAtEnd_afterDraining() throws {
        var r = ByteReader([0xAA, 0xBB])
        #expect(r.isAtEnd == false)
        _ = try r.readUInt16()
        #expect(r.isAtEnd == true)
    }

    @Test func reader_readRemaining_drainsTail() throws {
        var r = ByteReader([1, 2, 3, 4, 5])
        _ = try r.readUInt16()
        #expect(r.readRemaining() == [3, 4, 5])
        #expect(r.isAtEnd == true)
    }

    @Test func reader_skip_inRange_advancesCursor() throws {
        var r = ByteReader([1, 2, 3, 4])
        try r.skip(2)
        #expect(r.position == 2)
        #expect(try r.readUInt8() == 3)
    }

    @Test func reader_skip_overrun_throwsInsufficientBytes() {
        var r = ByteReader([1, 2])
        #expect(throws: ByteError.insufficientBytes(requested: 5, available: 2)) {
            try r.skip(5)
        }
    }

    @Test func reader_readBytes_advancesAndReturns() throws {
        var r = ByteReader([10, 20, 30, 40])
        #expect(try r.readBytes(3) == [10, 20, 30])
        #expect(r.position == 3)
    }

    @Test func reader_readByteBuffer_returnsBytes() throws {
        var r = ByteReader([5, 6, 7])
        let b = try r.readByteBuffer(2)
        #expect(b.toArray() == [5, 6])
    }

    @Test func reader_subReader_returnsIndependentCursor_parentAdvances() throws {
        var parent = ByteReader([1, 2, 3, 4, 5])
        var sub = try parent.subReader(length: 3)
        #expect(parent.position == 3)
        #expect(try sub.readUInt8() == 1)
        // Sub cursor is independent of the parent.
        #expect(parent.position == 3)
        #expect(try parent.readUInt8() == 4)
    }

    @Test func reader_remainingSpan_reflectsCursorAfterPartialRead() throws {
        var r = ByteReader([0xA0, 0xA1, 0xA2, 0xA3])
        _ = try r.readUInt8()
        let span = r.remainingSpan
        #expect(span.count == 3)
        var seen: [UInt8] = []
        for i in 0..<span.count { seen.append(span[i]) }
        #expect(seen == [0xA1, 0xA2, 0xA3])
    }

    @Test func reader_peekUInt8_doesNotAdvance() throws {
        let r = ByteReader([0x42, 0x43])
        #expect(try r.peekUInt8() == 0x42)
        #expect(r.position == 0)
    }
}
