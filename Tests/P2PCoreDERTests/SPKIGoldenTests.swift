// SPKIGoldenTests.swift
// Byte-for-byte SubjectPublicKeyInfo layouts from der-tls-impl.md §2.1, plus
// round-trip parse. P-256 (30 59), P-384, Ed25519 (30 2A).

import Testing
@testable import P2PCoreDER

@Suite("SubjectPublicKeyInfo golden bytes")
struct SPKIGoldenTests {

    /// A fixed 65-byte P-256 uncompressed point: 0x04 || X(32) || Y(32).
    static func p256Point() -> [UInt8] {
        var p = [UInt8]()
        p.append(0x04)
        for i in 0..<32 { p.append(UInt8(0x10 &+ UInt8(i))) }   // X
        for i in 0..<32 { p.append(UInt8(0x40 &+ UInt8(i))) }   // Y
        return p
    }

    @Test func p256_layout_3059() throws {
        let spki = try SubjectPublicKeyInfoDER.encodeP256(uncompressedPoint65: Self.p256Point())
        // Outer SEQUENCE, len 0x59 = 89; total 91.
        #expect(spki.count == 91)
        #expect(spki[0] == 0x30)
        #expect(spki[1] == 0x59)
        // AlgorithmIdentifier SEQUENCE len 0x13.
        #expect(spki[2] == 0x30)
        #expect(spki[3] == 0x13)
        // ecPublicKey OID.
        #expect(Array(spki[4..<13]) == [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        // secp256r1 OID (parameters).
        #expect(Array(spki[13..<23]) == [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
        // BIT STRING 03 42 00 04 <X><Y>.
        #expect(spki[23] == 0x03)
        #expect(spki[24] == 0x42)
        #expect(spki[25] == 0x00)   // unused bits
        #expect(spki[26] == 0x04)   // uncompressed point marker
        #expect(Array(spki[27..<91]) == Array(Self.p256Point().dropFirst()))
    }

    @Test func p256_roundTrip() throws {
        let spki = try SubjectPublicKeyInfoDER.encodeP256(uncompressedPoint65: Self.p256Point())
        let parsed = try SubjectPublicKeyInfoDER.parse(spki)
        #expect(parsed.curve == .p256)
        #expect(parsed.keyBytes == Self.p256Point())
        #expect(parsed.spkiDER == spki)   // verbatim
    }

    @Test func ed25519_layout_302A() throws {
        let key = [UInt8](repeating: 0xCD, count: 32)
        let spki = try SubjectPublicKeyInfoDER.encodeEd25519(rawKey32: key)
        // 30 2A 30 05 06 03 2B 65 70 03 21 00 <32>
        #expect(spki[0] == 0x30)
        #expect(spki[1] == 0x2A)   // 42
        #expect(Array(spki[2..<9]) == [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70])
        #expect(Array(spki[9..<12]) == [0x03, 0x21, 0x00])
        #expect(Array(spki[12..<44]) == key)
        #expect(spki.count == 44)
    }

    @Test func ed25519_roundTrip() throws {
        let key = [UInt8](repeating: 0xCD, count: 32)
        let spki = try SubjectPublicKeyInfoDER.encodeEd25519(rawKey32: key)
        let parsed = try SubjectPublicKeyInfoDER.parse(spki)
        #expect(parsed.curve == .ed25519)
        #expect(parsed.keyBytes == key)
    }

    @Test func p384_roundTrip_and_oid() throws {
        var point = [UInt8]()
        point.append(0x04)
        for i in 0..<96 { point.append(UInt8(truncatingIfNeeded: i)) }
        let spki = try SubjectPublicKeyInfoDER.encodeP384(uncompressedPoint97: point)
        // parameters OID secp384r1: 06 05 2B 81 04 00 22
        #expect(Array(spki[13..<20]) == [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22])
        let parsed = try SubjectPublicKeyInfoDER.parse(spki)
        #expect(parsed.curve == .p384)
        #expect(parsed.keyBytes == point)
    }

    @Test func parse_rejectsWrongPointLength() {
        // P-256 OID pair but a 64-byte BIT STRING -> valueTooLarge.
        let algorithm = DERWriter.sequence([
            DERWriter.encodeOID(.ecPublicKey),
            DERWriter.encodeOID(.secp256r1),
        ])
        let badKey = [UInt8](repeating: 0x04, count: 64)
        let spki = DERWriter.sequence([algorithm, DERWriter.encodeBitString(badKey)])
        #expect(throws: DERError.valueTooLarge) {
            _ = try SubjectPublicKeyInfoDER.parse(spki)
        }
    }

    @Test func parse_rejectsUnknownCurve() {
        // ecPublicKey + ed25519 OID as "parameters" -> unsupportedOID.
        let algorithm = DERWriter.sequence([
            DERWriter.encodeOID(.ecPublicKey),
            DERWriter.encodeOID(.ed25519),
        ])
        let key = [UInt8](repeating: 0x04, count: 65)
        let spki = DERWriter.sequence([algorithm, DERWriter.encodeBitString(key)])
        #expect(throws: DERError.unsupportedOID) {
            _ = try SubjectPublicKeyInfoDER.parse(spki)
        }
    }
}
