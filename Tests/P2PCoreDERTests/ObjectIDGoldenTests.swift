// ObjectIDGoldenTests.swift
// Pins the OID content bytes, including the corrected libp2p extension OID
// (53594 -> 0x83 0xA2 0x5A, NOT the prior doc's wrong 0x83 0x9A 0x1A).

import Testing
@testable import P2PCoreDER

@Suite("ObjectID golden bytes")
struct ObjectIDGoldenTests {

    @Test func libp2pExtensionOID_encodesTo_83A25A() {
        // 1.3.6.1.4.1.53594.1.1 content octets.
        #expect(ObjectID.libp2pExt.der == [0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01])
    }

    @Test func ecPublicKey_content() {
        #expect(ObjectID.ecPublicKey.der == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
    }

    @Test func secp256r1_content() {
        #expect(ObjectID.secp256r1.der == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    }

    @Test func secp384r1_content() {
        #expect(ObjectID.secp384r1.der == [0x2B, 0x81, 0x04, 0x00, 0x22])
    }

    @Test func ecdsaSHA256_content() {
        #expect(ObjectID.ecdsaSHA256.der == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])
    }

    @Test func ed25519_content() {
        #expect(ObjectID.ed25519.der == [0x2B, 0x65, 0x70])
    }

    /// Encode the full OID TLV and pin the wire form: 06 0A <10 content bytes>.
    @Test func libp2pExtensionOID_fullTLV() {
        let tlv = DERWriter.encodeOID(.libp2pExt)
        #expect(tlv == [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01])
    }

    /// Independently re-derive 53594's base-128 encoding to guard the constant.
    @Test func subidentifier_53594_base128() {
        var value: UInt = 53594
        var groups: [UInt8] = []
        groups.append(UInt8(value & 0x7F))
        value >>= 7
        while value > 0 {
            groups.append(UInt8((value & 0x7F) | 0x80))
            value >>= 7
        }
        let encoded = Array(groups.reversed())
        #expect(encoded == [0x83, 0xA2, 0x5A])
    }
}
