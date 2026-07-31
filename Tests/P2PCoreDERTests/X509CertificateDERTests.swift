import Testing
@testable import P2PCoreDER

@Suite("X.509 certificate DER")
struct X509CertificateDERTests {
    @Test func extractsP256SubjectPublicKeyInfo() throws {
        let point = SPKIGoldenTests.p256Point()
        let spki = try SubjectPublicKeyInfoDER.encodeP256(uncompressedPoint65: point)
        let certificate = try Self.certificate(spki: spki)

        let parsed = try X509CertificateDER.subjectPublicKeyInfo(in: certificate)

        #expect(parsed.curve == .p256)
        #expect(parsed.keyBytes == point)
        #expect(parsed.spkiDER == spki)
    }

    @Test func acceptsV1CertificateWithoutExplicitVersion() throws {
        let point = SPKIGoldenTests.p256Point()
        let spki = try SubjectPublicKeyInfoDER.encodeP256(uncompressedPoint65: point)
        let certificate = try Self.certificate(spki: spki, includesVersion: false)

        let parsed = try X509CertificateDER.subjectPublicKeyInfo(in: certificate)

        #expect(parsed.keyBytes == point)
    }

    @Test func acceptsOrderedOptionalFieldsAfterSubjectPublicKeyInfo() throws {
        let spki = try SubjectPublicKeyInfoDER.encodeP256(
            uncompressedPoint65: SPKIGoldenTests.p256Point()
        )
        let optionals = [
            DERWriter.encode(.context1Primitive, [0x00]),
            DERWriter.encode(.context2Primitive, [0x00]),
            DERWriter.encode(.context3, DERWriter.sequence([])),
        ]
        let certificate = try Self.certificate(spki: spki, optionalFields: optionals)

        let parsed = try X509CertificateDER.subjectPublicKeyInfo(in: certificate)

        #expect(parsed.spkiDER == spki)
    }

    @Test func rejectsTrailingBytesOutsideCertificate() throws {
        let spki = try SubjectPublicKeyInfoDER.encodeP256(
            uncompressedPoint65: SPKIGoldenTests.p256Point()
        )
        var certificate = try Self.certificate(spki: spki)
        certificate.append(0x00)

        #expect(throws: DERError.trailingBytes) {
            _ = try X509CertificateDER.subjectPublicKeyInfo(in: certificate)
        }
    }

    @Test func rejectsUnknownFieldAfterSubjectPublicKeyInfo() throws {
        let spki = try SubjectPublicKeyInfoDER.encodeP256(
            uncompressedPoint65: SPKIGoldenTests.p256Point()
        )
        let certificate = try Self.certificate(
            spki: spki,
            optionalFields: [DERWriter.encodeOctetString([0x01])]
        )

        #expect(throws: DERError.invalidCertificateStructure) {
            _ = try X509CertificateDER.subjectPublicKeyInfo(in: certificate)
        }
    }

    @Test func rejectsBareSubjectPublicKeyInfo() throws {
        let spki = try SubjectPublicKeyInfoDER.encodeP256(
            uncompressedPoint65: SPKIGoldenTests.p256Point()
        )

        #expect(throws: DERError.invalidCertificateStructure) {
            _ = try X509CertificateDER.subjectPublicKeyInfo(in: spki)
        }
    }

    private static func certificate(
        spki: [UInt8],
        includesVersion: Bool = true,
        optionalFields: [[UInt8]] = []
    ) throws -> [UInt8] {
        var fields = [[UInt8]]()
        if includesVersion {
            fields.append(DERWriter.encode(.context0, DERWriter.encodeInteger([0x02])))
        }
        fields.append(DERWriter.encodeInteger([0x01]))
        fields.append(Self.signatureAlgorithm)
        fields.append(DERWriter.sequence([]))

        var validity = DERWriter()
        validity.appendUTCTime(epochSeconds: 1_750_550_400)
        validity.appendUTCTime(epochSeconds: 1_782_086_400)
        fields.append(DERWriter.sequence([validity.finish()]))
        fields.append(DERWriter.sequence([]))
        fields.append(spki)
        fields.append(contentsOf: optionalFields)

        return DERWriter.sequence([
            DERWriter.sequence(fields),
            Self.signatureAlgorithm,
            DERWriter.encodeBitString([0x01]),
        ])
    }

    private static var signatureAlgorithm: [UInt8] {
        DERWriter.sequence([DERWriter.encodeOID(.ecdsaSHA256)])
    }
}
