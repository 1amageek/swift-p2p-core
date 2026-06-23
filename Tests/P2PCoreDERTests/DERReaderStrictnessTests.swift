// DERReaderStrictnessTests.swift
// Fail-closed negatives: every malformed-DER condition yields a specific typed
// error, never a silent accept. Strict DER rejects BER indefinite length,
// non-minimal lengths, trailing garbage, wrong tags, and bad BIT STRING padding.

import Testing
@testable import P2PCoreDER

@Suite("DERReader strictness (fail-closed)")
struct DERReaderStrictnessTests {

    @Test func truncated_content() {
        // OCTET STRING declares 5 bytes but only 2 present.
        var r = DERReader([0x04, 0x05, 0xAA, 0xBB])
        #expect(throws: DERError.truncated) {
            _ = try r.readOctetString()
        }
    }

    @Test func truncated_atTag() {
        var r = DERReader([])
        #expect(throws: DERError.truncated) {
            _ = try r.readTLV()
        }
    }

    @Test func indefiniteLength_rejected() {
        // tag 0x30, length 0x80 (indefinite).
        var r = DERReader([0x30, 0x80, 0x00, 0x00])
        #expect(throws: DERError.indefiniteLength) {
            _ = try r.readTLV()
        }
    }

    @Test func nonMinimalLength_leadingZero() {
        // long form 0x81 0x00 -> leading zero length octet.
        var r = DERReader([0x04, 0x81, 0x00])
        #expect(throws: DERError.nonMinimalLength) {
            _ = try r.readTLV()
        }
    }

    @Test func nonMinimalLength_longFormForSmallValue() {
        // 0x81 0x05 encodes 5 in long form where short form must be used.
        var r = DERReader([0x04, 0x81, 0x05, 1, 2, 3, 4, 5])
        #expect(throws: DERError.nonMinimalLength) {
            _ = try r.readTLV()
        }
    }

    @Test func trailingBytes_insideConstructed() {
        // SEQUENCE { OCTET STRING[1] } but content has an extra byte the body
        // does not consume.
        // 30 04  04 01 AA  FF   (FF is trailing inside the SEQUENCE content)
        var r = DERReader([0x30, 0x04, 0x04, 0x01, 0xAA, 0xFF])
        #expect(throws: DERError.trailingBytes) {
            try r.readConstructed(.sequence) { (inner) throws(DERError) in
                _ = try inner.readOctetString()
            }
        }
    }

    @Test func unexpectedTag() {
        // Expect SEQUENCE, find OCTET STRING.
        var r = DERReader([0x04, 0x01, 0xAA])
        #expect(throws: DERError.unexpectedTag(found: 0x04, wanted: 0x30)) {
            try r.readConstructed(.sequence) { (_) throws(DERError) in }
        }
    }

    @Test func bitString_nonZeroPadding_rejected() {
        // BIT STRING with unused-bits = 0x03.
        var r = DERReader([0x03, 0x02, 0x03, 0xAA])
        #expect(throws: DERError.nonZeroBitStringPadding(0x03)) {
            _ = try r.readBitString()
        }
    }

    @Test func bitString_empty_rejected() {
        // BIT STRING with zero content (no unused-bits octet).
        var r = DERReader([0x03, 0x00])
        #expect(throws: DERError.bitStringEmpty) {
            _ = try r.readBitString()
        }
    }

    @Test func boolean_nonCanonical_rejected() {
        // BOOLEAN true must be 0xFF; 0x01 is non-canonical DER.
        var r = DERReader([0x01, 0x01, 0x01])
        #expect(throws: DERError.malformedBoolean) {
            _ = try r.readBoolean()
        }
    }

    @Test func integer_empty_rejected() {
        var r = DERReader([0x02, 0x00])
        #expect(throws: DERError.integerEmpty) {
            _ = try r.readIntegerBytes()
        }
    }

    @Test func longForm_validTwoOctetLength() throws {
        // 0x81 0x80 = 128 in long form (minimal — value >= 128).
        let content = [UInt8](repeating: 0xAB, count: 128)
        var bytes: [UInt8] = [0x04, 0x81, 0x80]
        bytes.append(contentsOf: content)
        var r = DERReader(bytes)
        let (tag, c) = try r.readTLV()
        #expect(tag == 0x04)
        #expect(c == content)
    }

    @Test func parseLeaf_garbageCertDER_throws() {
        #expect(throws: DERError.self) {
            _ = try LibP2PCertificateDER.parseLeaf([0xFF, 0xFF, 0xFF])
        }
    }
}
