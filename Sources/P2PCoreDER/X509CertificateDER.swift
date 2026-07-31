// X509CertificateDER.swift
// Strict, Foundation-free extraction of SubjectPublicKeyInfo from an RFC 5280
// certificate. This is a provisioning/handshake boundary, not a packet hot path.

/// Extracts the public-key description from a DER-encoded X.509 certificate.
///
/// The parser validates the outer `Certificate` and ordered `TBSCertificate`
/// envelope, captures the SubjectPublicKeyInfo bytes verbatim, and delegates the
/// supported-key validation to ``SubjectPublicKeyInfoDER``. It intentionally does
/// not perform CA-path or certificate-signature validation. Protocols such as
/// WebRTC authenticate the complete leaf through an out-of-band fingerprint and
/// separately prove possession of the extracted key during DTLS.
public enum X509CertificateDER {
    /// Returns the supported SubjectPublicKeyInfo embedded in `certificateDER`.
    ///
    /// - Throws: ``DERError`` when the certificate envelope is malformed, has
    ///   trailing bytes, or carries an unsupported public-key algorithm.
    public static func subjectPublicKeyInfo(
        in certificateDER: [UInt8]
    ) throws(DERError) -> SubjectPublicKeyInfoDER.Parsed {
        var certificateReader = DERReader(certificateDER)
        var spkiDER = [UInt8]()

        try certificateReader.readConstructed(.sequence) { (certificate) throws(DERError) in
            try certificate.readConstructed(.sequence) { (tbsCertificate) throws(DERError) in
                if tbsCertificate.peekTag() == DERTag.context0.rawValue {
                    try tbsCertificate.readConstructed(.context0) { (version) throws(DERError) in
                        _ = try version.readIntegerBytes()
                    }
                }

                guard tbsCertificate.peekTag() == DERTag.integer.rawValue else {
                    throw .invalidCertificateStructure
                }
                _ = try tbsCertificate.readIntegerBytes()
                try skipExpected(.sequence, in: &tbsCertificate) // signature
                try skipExpected(.sequence, in: &tbsCertificate) // issuer
                try skipExpected(.sequence, in: &tbsCertificate) // validity
                try skipExpected(.sequence, in: &tbsCertificate) // subject

                guard tbsCertificate.peekTag() == DERTag.sequence.rawValue else {
                    throw .invalidCertificateStructure
                }
                spkiDER = try tbsCertificate.captureRawTLV()

                // issuerUniqueID [1], subjectUniqueID [2], and extensions [3]
                // are optional and ordered by RFC 5280. Their contents are not
                // authentication inputs here, but their envelope must be strict.
                if tbsCertificate.peekTag() == DERTag.context1Primitive.rawValue {
                    try tbsCertificate.skip()
                }
                if tbsCertificate.peekTag() == DERTag.context2Primitive.rawValue {
                    try tbsCertificate.skip()
                }
                if tbsCertificate.peekTag() == DERTag.context3.rawValue {
                    try tbsCertificate.skip()
                }
                guard tbsCertificate.isAtEnd else {
                    throw .invalidCertificateStructure
                }
            }

            try certificate.readConstructed(.sequence) { (signatureAlgorithm) throws(DERError) in
                _ = try signatureAlgorithm.readOID()
                while !signatureAlgorithm.isAtEnd {
                    try signatureAlgorithm.skip()
                }
            }
            let signature = try certificate.readBitString()
            guard !signature.isEmpty else {
                throw .invalidCertificateStructure
            }
        }

        guard certificateReader.isAtEnd else {
            throw .trailingBytes
        }
        guard !spkiDER.isEmpty else {
            throw .invalidCertificateStructure
        }
        return try SubjectPublicKeyInfoDER.parse(spkiDER)
    }

    private static func skipExpected(
        _ tag: DERTag,
        in reader: inout DERReader
    ) throws(DERError) {
        guard reader.peekTag() == tag.rawValue else {
            throw .invalidCertificateStructure
        }
        try reader.skip()
    }
}
