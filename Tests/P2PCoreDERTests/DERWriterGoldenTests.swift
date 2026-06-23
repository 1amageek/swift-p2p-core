// DERWriterGoldenTests.swift
// Golden bytes for the primitive writers: minimal length encoding (short + long
// form), INTEGER sign-safe minimization, BIT STRING unused-bits framing, BOOLEAN.

import Testing
@testable import P2PCoreDER

@Suite("DERWriter golden bytes")
struct DERWriterGoldenTests {

    // MARK: Length encoding

    @Test func shortFormLength() {
        // content of 5 bytes -> 0x04 0x05 <5 bytes>
        let tlv = DERWriter.encodeOctetString([1, 2, 3, 4, 5])
        #expect(tlv == [0x04, 0x05, 1, 2, 3, 4, 5])
    }

    @Test func shortFormLength_127_boundary() {
        let content = [UInt8](repeating: 0xAB, count: 127)
        let tlv = DERWriter.encode(.octetString, content)
        #expect(tlv[0] == 0x04)
        #expect(tlv[1] == 0x7F)        // 127 still short form
        #expect(tlv.count == 2 + 127)
    }

    @Test func longFormLength_128() {
        let content = [UInt8](repeating: 0xAB, count: 128)
        let tlv = DERWriter.encode(.octetString, content)
        #expect(tlv[0] == 0x04)
        #expect(tlv[1] == 0x81)        // long form, 1 octet
        #expect(tlv[2] == 0x80)        // 128
        #expect(tlv.count == 3 + 128)
    }

    @Test func longFormLength_300() {
        let content = [UInt8](repeating: 0xAB, count: 300)
        let tlv = DERWriter.encode(.octetString, content)
        #expect(tlv[0] == 0x04)
        #expect(tlv[1] == 0x82)        // long form, 2 octets
        #expect(tlv[2] == 0x01)        // 0x012C = 300
        #expect(tlv[3] == 0x2C)
        #expect(tlv.count == 4 + 300)
    }

    // MARK: INTEGER minimization (matches ASN1Builder.integer)

    @Test func integer_highBitSet_prependsZero() {
        // 0x80 has high bit set -> 0x02 0x02 0x00 0x80
        let tlv = DERWriter.encodeInteger([0x80])
        #expect(tlv == [0x02, 0x02, 0x00, 0x80])
    }

    @Test func integer_leadingZeroStripped() {
        // 0x00 0x7F -> strip leading zero -> 0x02 0x01 0x7F
        let tlv = DERWriter.encodeInteger([0x00, 0x7F])
        #expect(tlv == [0x02, 0x01, 0x7F])
    }

    @Test func integer_leadingZeroKeptForSign() {
        // 0x00 0x80 -> next byte high bit set, keep -> 0x02 0x02 0x00 0x80
        let tlv = DERWriter.encodeInteger([0x00, 0x80])
        #expect(tlv == [0x02, 0x02, 0x00, 0x80])
    }

    @Test func integer_serial16_positive_noSignByte() {
        // High bit already cleared by caller (serial[0] &= 0x7F) -> emitted verbatim.
        var serial = [UInt8](repeating: 0x11, count: 16)
        serial[0] &= 0x7F
        let tlv = DERWriter.encodeInteger(serial)
        #expect(tlv[0] == 0x02)
        #expect(tlv[1] == 0x10)        // 16 bytes, no sign prepend
        #expect(Array(tlv.dropFirst(2)) == serial)
    }

    // MARK: BIT STRING

    @Test func bitString_prependsUnusedBitsOctet() {
        let tlv = DERWriter.encodeBitString([0xAA, 0xBB])
        #expect(tlv == [0x03, 0x03, 0x00, 0xAA, 0xBB])
    }

    // MARK: BOOLEAN

    @Test func boolean_true_isFF() {
        #expect(DERWriter.encodeBoolean(true) == [0x01, 0x01, 0xFF])
    }

    @Test func boolean_false_is00() {
        #expect(DERWriter.encodeBoolean(false) == [0x01, 0x01, 0x00])
    }

    // MARK: SEQUENCE assembly

    @Test func emptySequence_is3000() {
        #expect(DERWriter.sequence([]) == [0x30, 0x00])
    }

    @Test func sequence_concatenatesChildren() {
        let a = DERWriter.encodeBoolean(true)      // 01 01 FF
        let b = DERWriter.encodeOctetString([0x42]) // 04 01 42
        let seq = DERWriter.sequence([a, b])
        #expect(seq == [0x30, 0x06, 0x01, 0x01, 0xFF, 0x04, 0x01, 0x42])
    }
}
