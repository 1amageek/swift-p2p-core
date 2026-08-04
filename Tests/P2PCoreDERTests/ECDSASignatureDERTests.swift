import Testing
@testable import P2PCoreDER

@Suite("Strict ECDSA DER codec")
struct ECDSASignatureDERTests {
    @Test("Canonical DER round-trips fixed-width scalars")
    func canonicalRoundTrip() throws {
        var raw = [UInt8](repeating: 0, count: 64)
        raw[0] = 0x80
        raw[31] = 0x01
        raw[32] = 0x00
        raw[63] = 0x7F

        let der = try ECDSASignatureDER.encode(
            rawRepresentation: raw,
            scalarByteCount: 32
        )
        let decoded = try ECDSASignatureDER.decode(
            derRepresentation: der,
            scalarByteCount: 32
        )

        #expect(decoded == raw)
    }

    @Test("Non-minimal and negative INTEGERs are rejected")
    func rejectsNonCanonicalIntegers() {
        let redundantZero = [UInt8]([
            0x30, 0x07,
            0x02, 0x02, 0x00, 0x01,
            0x02, 0x01, 0x01,
        ])
        let negative = [UInt8]([
            0x30, 0x06,
            0x02, 0x01, 0x80,
            0x02, 0x01, 0x01,
        ])

        #expect(throws: DERError.nonMinimalInteger) {
            _ = try ECDSASignatureDER.decode(
                derRepresentation: redundantZero,
                scalarByteCount: 32
            )
        }
        #expect(throws: DERError.negativeInteger) {
            _ = try ECDSASignatureDER.decode(
                derRepresentation: negative,
                scalarByteCount: 32
            )
        }
    }

    @Test("Oversized scalar and trailing bytes are rejected")
    func rejectsOversizedAndTrailingRepresentations() throws {
        let oversizedInteger = DERWriter.encode(
            .integer,
            [UInt8](repeating: 0x01, count: 33)
        )
        let validInteger = DERWriter.encodeInteger([0x01])
        let oversized = DERWriter.sequence([oversizedInteger, validInteger])

        #expect(throws: DERError.integerOutOfRange(
            maximumByteCount: 32,
            actualByteCount: 33
        )) {
            _ = try ECDSASignatureDER.decode(
                derRepresentation: oversized,
                scalarByteCount: 32
            )
        }

        var valid = try ECDSASignatureDER.encode(
            rawRepresentation: [UInt8](repeating: 0x01, count: 64),
            scalarByteCount: 32
        )
        valid.append(0x00)
        #expect(throws: DERError.trailingBytes) {
            _ = try ECDSASignatureDER.decode(
                derRepresentation: valid,
                scalarByteCount: 32
            )
        }
    }

    @Test("Invalid scalar widths are rejected before allocation")
    func rejectsInvalidScalarWidths() {
        #expect(throws: DERError.valueTooLarge) {
            _ = try ECDSASignatureDER.decode(
                derRepresentation: [],
                scalarByteCount: 0
            )
        }
        #expect(throws: DERError.valueTooLarge) {
            _ = try ECDSASignatureDER.decode(
                derRepresentation: [],
                scalarByteCount: Int.max
            )
        }
    }
}
