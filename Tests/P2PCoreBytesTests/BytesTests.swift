// BytesTests.swift
// Value semantics, borrowed views, inits, slicing, and append for `Bytes`.

import Testing
@testable import P2PCoreBytes

@Suite("Bytes")
struct BytesTests {
    @Test func bytes_initEmpty_isEmpty() {
        let b = Bytes()
        #expect(b.isEmpty)
        #expect(b.count == 0)
    }

    @Test func bytes_initArray_roundTripsToArray() {
        let source: [UInt8] = [1, 2, 3, 4, 5]
        let b = Bytes(source)
        #expect(b.toArray() == source)
        #expect(b.count == 5)
    }

    @Test func bytes_initSequence_copies() {
        let b = Bytes((0..<4).map { UInt8($0) })
        #expect(b.toArray() == [0, 1, 2, 3])
    }

    @Test func bytes_span_exposesSameBytesAndCount() {
        let source: [UInt8] = [10, 20, 30]
        let b = Bytes(source)
        let span = b.span
        #expect(span.count == 3)
        var seen: [UInt8] = []
        for i in 0..<span.count { seen.append(span[i]) }
        #expect(seen == source)
    }

    @Test func bytes_rawSpan_exposesSameBytesAndByteCount() {
        let source: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD]
        let b = Bytes(source)
        let raw = b.rawSpan
        #expect(raw.byteCount == 4)
        var seen: [UInt8] = []
        for i in 0..<raw.byteCount {
            seen.append(raw.unsafeLoad(fromByteOffset: i, as: UInt8.self))
        }
        #expect(seen == source)
    }

    @Test func bytes_initFromSpan_copiesView() {
        let source: [UInt8] = [7, 8, 9]
        let original = Bytes(source)
        let copy = Bytes(original.span)
        #expect(copy.toArray() == source)
    }

    @Test func bytes_initFromRawSpan_copiesView() {
        let source: [UInt8] = [0x01, 0x02, 0x03]
        let original = Bytes(source)
        let copy = Bytes(original.rawSpan)
        #expect(copy.toArray() == source)
    }

    @Test func bytes_subscript_returnsElement() {
        let b = Bytes([100, 101, 102])
        #expect(b[0] == 100)
        #expect(b[2] == 102)
    }

    @Test func bytes_slice_inRange_returnsSubBytes() throws {
        let b = Bytes([0, 1, 2, 3, 4, 5])
        let sub = try b.slice(2..<5)
        #expect(sub.toArray() == [2, 3, 4])
    }

    @Test func bytes_slice_negativeLower_throwsIndexOutOfRange() {
        let b = Bytes([0, 1, 2])
        #expect(throws: ByteError.indexOutOfRange) {
            _ = try b.slice(-1..<2)
        }
    }

    @Test func bytes_slice_upperPastEnd_throwsIndexOutOfRange() {
        let b = Bytes([0, 1, 2])
        #expect(throws: ByteError.indexOutOfRange) {
            _ = try b.slice(0..<4)
        }
    }

    @Test func bytes_sliceAtCount_inRange_ok() throws {
        let b = Bytes([10, 11, 12, 13])
        let sub = try b.slice(at: 1, count: 2)
        #expect(sub.toArray() == [11, 12])
    }

    @Test func bytes_sliceAtCount_overrun_throwsIndexOutOfRange() {
        let b = Bytes([10, 11, 12])
        #expect(throws: ByteError.indexOutOfRange) {
            _ = try b.slice(at: 2, count: 5)
        }
    }

    @Test func bytes_concat_operator_appends() {
        let a = Bytes([1, 2])
        let b = Bytes([3, 4, 5])
        let c = a + b
        #expect(c.toArray() == [1, 2, 3, 4, 5])
    }

    @Test func bytes_appendBytes_grows() {
        var a = Bytes([1, 2])
        a.append(Bytes([3, 4]))
        a.append(contentsOf: [5, 6])
        #expect(a.toArray() == [1, 2, 3, 4, 5, 6])
    }

    @Test func bytes_equatable_hashable_valueSemantics() {
        let a = Bytes([1, 2, 3])
        let b = Bytes([1, 2, 3])
        let c = Bytes([1, 2, 4])
        #expect(a == b)
        #expect(a != c)
        #expect(a.hashValue == b.hashValue)
    }
}
