// ByteReaderNonCopyableTests.swift
// Ownership behavior of the `~Copyable` ByteReader: borrow without consuming,
// and consuming move transfers ownership.

import Testing
@testable import P2PCoreBytes

/// Reads the first byte through a borrow, without consuming the reader.
private func firstByte(borrowing reader: borrowing ByteReader) throws(ByteError) -> UInt8 {
    try reader.peekUInt8()
}

/// Takes ownership of a reader and drains it to the end.
private func drain(consuming reader: consuming ByteReader) -> [UInt8] {
    reader.readRemaining()
}

@Suite("ByteReader ~Copyable")
struct ByteReaderNonCopyableTests {
    @Test func reader_borrowingHelper_canReadWithoutConsuming() throws {
        let reader = ByteReader([0x09, 0x08, 0x07])
        let first = try firstByte(borrowing: reader)
        #expect(first == 0x09)
        // The reader is still usable after the borrow.
        #expect(reader.count == 3)
    }

    @Test func reader_consumingMove_transfersOwnership() {
        let reader = ByteReader([1, 2, 3])
        let drained = drain(consuming: reader)
        #expect(drained == [1, 2, 3])
    }
}
