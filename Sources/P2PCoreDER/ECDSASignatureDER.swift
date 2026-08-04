// Strict DER codec for fixed-width ECDSA signatures. Embedded-clean: owned
// byte arrays, typed errors, and no Foundation or existential dependencies.

/// Converts fixed-width IEEE P1363 `r || s` signatures to and from the strict
/// DER `SEQUENCE { INTEGER r, INTEGER s }` representation used on TLS and
/// libp2p identity wire boundaries.
public enum ECDSASignatureDER {
    /// Encodes two fixed-width unsigned scalars as a canonical DER signature.
    public static func encode(
        rawRepresentation: [UInt8],
        scalarByteCount: Int
    ) throws(DERError) -> [UInt8] {
        guard scalarByteCount > 0,
              scalarByteCount <= Int.max / 2 else {
            throw .valueTooLarge
        }
        let expectedByteCount = scalarByteCount * 2
        guard rawRepresentation.count == expectedByteCount else {
            throw .invalidECDSASignatureLength(
                expected: expectedByteCount,
                actual: rawRepresentation.count
            )
        }

        let r = Array(rawRepresentation[0..<scalarByteCount])
        let s = Array(rawRepresentation[scalarByteCount..<expectedByteCount])
        return DERWriter.sequence([
            DERWriter.encodeInteger(r),
            DERWriter.encodeInteger(s),
        ])
    }

    /// Decodes a canonical DER signature to two fixed-width unsigned scalars.
    ///
    /// Negative, non-minimal, over-wide, truncated, and trailing encodings are
    /// rejected before a raw signature is returned.
    public static func decode(
        derRepresentation: [UInt8],
        scalarByteCount: Int
    ) throws(DERError) -> [UInt8] {
        guard scalarByteCount > 0,
              scalarByteCount <= Int.max / 2 else {
            throw .valueTooLarge
        }

        var reader = DERReader(derRepresentation)
        let scalars = try reader.readConstructed(.sequence) { inner throws(DERError) in
            let r = try inner.readCanonicalNonNegativeIntegerBytes()
            let s = try inner.readCanonicalNonNegativeIntegerBytes()
            return (r, s)
        }
        guard reader.isAtEnd else {
            throw .trailingBytes
        }

        let r = try fixedWidthUnsignedInteger(
            scalars.0,
            scalarByteCount: scalarByteCount
        )
        let s = try fixedWidthUnsignedInteger(
            scalars.1,
            scalarByteCount: scalarByteCount
        )

        var rawRepresentation = [UInt8]()
        rawRepresentation.reserveCapacity(scalarByteCount * 2)
        rawRepresentation.append(contentsOf: r)
        rawRepresentation.append(contentsOf: s)
        return rawRepresentation
    }

    private static func fixedWidthUnsignedInteger(
        _ canonicalInteger: [UInt8],
        scalarByteCount: Int
    ) throws(DERError) -> [UInt8] {
        let significantStart = canonicalInteger.count > 1 && canonicalInteger[0] == 0x00
            ? 1
            : 0
        let significantByteCount = canonicalInteger.count - significantStart
        guard significantByteCount <= scalarByteCount else {
            throw .integerOutOfRange(
                maximumByteCount: scalarByteCount,
                actualByteCount: significantByteCount
            )
        }

        var fixedWidth = [UInt8](
            repeating: 0,
            count: scalarByteCount - significantByteCount
        )
        fixedWidth.append(contentsOf: canonicalInteger[significantStart...])
        return fixedWidth
    }
}
