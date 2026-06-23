// SignedKeyAndCertGoldenTests.swift
// Golden bytes + round-trips for the SignedKey extension value, the cert
// envelope (deterministic signer + fixed serial/epochs), and parseLeaf.

import Testing
@testable import P2PCoreDER

@Suite("SignedKey + certificate golden bytes")
struct SignedKeyAndCertGoldenTests {

    // MARK: SignedKey extension value

    @Test func signedKey_layout() {
        let pb: [UInt8] = [0x08, 0x01, 0x12, 0x02, 0xDE, 0xAD]  // tiny protobuf
        let sig: [UInt8] = [0xBE, 0xEF]
        let der = LibP2PSignedKeyDER.encode(protobufPubKey: pb, signature: sig)
        // SEQUENCE { OCTET STRING pb, OCTET STRING sig }
        // 30 0C  04 06 08 01 12 02 DE AD  04 02 BE EF
        #expect(der == [0x30, 0x0C, 0x04, 0x06, 0x08, 0x01, 0x12, 0x02, 0xDE, 0xAD, 0x04, 0x02, 0xBE, 0xEF])
    }

    @Test func signedKey_roundTrip() throws {
        let pb = [UInt8](repeating: 0x11, count: 36)
        let sig = [UInt8](repeating: 0x22, count: 70)
        let der = LibP2PSignedKeyDER.encode(protobufPubKey: pb, signature: sig)
        let (parsedPub, parsedSig) = try LibP2PSignedKeyDER.parse(der)
        #expect(parsedPub == pb)
        #expect(parsedSig == sig)
    }

    @Test func signedKey_parse_toleratesTrailingChild() throws {
        // SEQUENCE { OCTET STRING, OCTET STRING, OCTET STRING } — extra ignored.
        let der = DERWriter.sequence([
            DERWriter.encodeOctetString([0x01]),
            DERWriter.encodeOctetString([0x02]),
            DERWriter.encodeOctetString([0x03]),
        ])
        let (pub, sig) = try LibP2PSignedKeyDER.parse(der)
        #expect(pub == [0x01])
        #expect(sig == [0x02])
    }

    // MARK: Certificate envelope (deterministic)

    /// A 65-byte P-256 point reused as the leaf SPKI source.
    static func spkiDER() throws -> [UInt8] {
        try SubjectPublicKeyInfoDER.encodeP256(uncompressedPoint65: SPKIGoldenTests.p256Point())
    }

    static func signedKeyExtension() -> [UInt8] {
        let pb = [UInt8](repeating: 0xA1, count: 36)
        let sig = [UInt8](repeating: 0xB2, count: 71)
        return LibP2PSignedKeyDER.encode(protobufPubKey: pb, signature: sig)
    }

    @Test func cert_structure_isDeterministic_andParses() throws {
        let spki = try Self.spkiDER()
        let ext = Self.signedKeyExtension()
        var serial = [UInt8](repeating: 0x33, count: 16)
        serial[0] &= 0x7F
        // 2026-06-22T00:00:00Z and +1y, both < 2050 (UTCTime range).
        let notBefore: Int64 = 1_750_550_400
        let notAfter: Int64 = 1_782_086_400
        let fixedSig: [UInt8] = [UInt8](repeating: 0x5A, count: 70)

        let cert = LibP2PCertificateDER.buildSelfSignedCert(
            spkiDER: spki,
            signedKeyExtension: ext,
            serial16: serial,
            notBefore: notBefore,
            notAfter: notAfter,
            signFn: { _ in fixedSig }
        )

        // Outer Certificate is a SEQUENCE.
        #expect(cert[0] == 0x30)

        // Determinism: same inputs -> identical bytes.
        let cert2 = LibP2PCertificateDER.buildSelfSignedCert(
            spkiDER: spki, signedKeyExtension: ext, serial16: serial,
            notBefore: notBefore, notAfter: notAfter, signFn: { _ in fixedSig }
        )
        #expect(cert == cert2)

        // parseLeaf extracts the verbatim SPKI + the extension value.
        let leaf = try LibP2PCertificateDER.parseLeaf(cert)
        #expect(leaf.spkiDER == spki)
        #expect(leaf.libp2pExtensionValue == ext)
    }

    @Test func cert_TBS_fieldOrder() throws {
        let spki = try Self.spkiDER()
        let ext = Self.signedKeyExtension()
        var serial = [UInt8](repeating: 0x01, count: 16)
        serial[0] &= 0x7F
        let cert = LibP2PCertificateDER.buildSelfSignedCert(
            spkiDER: spki, signedKeyExtension: ext, serial16: serial,
            notBefore: 1_750_550_400, notAfter: 1_782_086_400, signFn: { _ in [UInt8](repeating: 0x00, count: 70) }
        )
        // Drill into outer SEQUENCE -> TBS -> first child is [0] EXPLICIT version A0 03 02 01 02.
        var outer = DERReader(cert)
        let leafCheck = try LibP2PCertificateDER.parseLeaf(cert)
        #expect(leafCheck.spkiDER == spki)
        // Manually confirm version tag bytes appear right after TBS SEQUENCE header.
        let (_, outerContent) = try outer.readTLV()
        var body = DERReader(outerContent)
        let (tbsTag, tbsContent) = try body.readTLV()
        #expect(tbsTag == 0x30)
        // First 5 bytes of TBS content: A0 03 02 01 02 (version v3).
        #expect(Array(tbsContent.prefix(5)) == [0xA0, 0x03, 0x02, 0x01, 0x02])
    }

    // MARK: parseLeaf fail-closed

    @Test func parseLeaf_missingExtension_returnsNil() throws {
        // Build a cert with NO extensions block: TBS without [3].
        let spki = try Self.spkiDER()
        let version = DERWriter.encode(.context0, DERWriter.encodeInteger([0x02]))
        let serial = DERWriter.encodeInteger([0x01])
        let sigAlg = DERWriter.sequence([DERWriter.encodeOID(.ecdsaSHA256)])
        let emptyName = DERWriter.sequence([])
        var vw = DERWriter()
        vw.appendUTCTime(epochSeconds: 1_750_550_400)
        vw.appendUTCTime(epochSeconds: 1_782_086_400)
        let validity = DERWriter.sequence([vw.finish()])
        let tbs = DERWriter.sequence([version, serial, sigAlg, emptyName, validity, emptyName, spki])
        let cert = DERWriter.sequence([tbs, sigAlg, DERWriter.encodeBitString([0x00])])

        let leaf = try LibP2PCertificateDER.parseLeaf(cert)
        #expect(leaf.spkiDER == spki)
        #expect(leaf.libp2pExtensionValue == nil)
    }
}
