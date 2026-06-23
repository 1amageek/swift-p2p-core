// LibP2PCertificateDER.swift
// The libp2p self-signed certificate envelope: build (write) + parseLeaf (the
// ~5-TLV fast path that extracts only the SPKI + libp2p extension value).
// Byte-identical to LibP2PCertificateHelper.buildCertificate. Embedded-clean:
// no Foundation, no `any`.

/// Builds and parses the libp2p self-signed leaf certificate.
///
/// The certificate is the minimal shape libp2p emits: version v3, a 16-byte
/// serial, ecdsa-with-SHA256 signature algorithm, empty issuer/subject names,
/// validity, the ephemeral P-256 SubjectPublicKeyInfo, and exactly one critical
/// extension carrying the SignedKey (OID `1.3.6.1.4.1.53594.1.1`). No
/// BasicConstraints / KeyUsage / SAN / name RDNs — none occur on the libp2p path.
public enum LibP2PCertificateDER {

    /// The fields `parseLeaf` extracts (everything libp2p actually needs).
    public struct LeafView: Sendable, Equatable {
        /// The leaf SubjectPublicKeyInfo, verbatim — this is the SignedKey verify message.
        public let spkiDER: [UInt8]
        /// The libp2p extension value, or `nil` if absent (caller fails closed).
        public let libp2pExtensionValue: [UInt8]?

        public init(spkiDER: [UInt8], libp2pExtensionValue: [UInt8]?) {
            self.spkiDER = spkiDER
            self.libp2pExtensionValue = libp2pExtensionValue
        }
    }

    // MARK: Build

    /// Builds and self-signs a libp2p leaf certificate.
    ///
    /// - Parameters:
    ///   - spkiDER: The ephemeral P-256 SubjectPublicKeyInfo (also the TLS leaf key).
    ///   - signedKeyExtension: The SignedKey DER value (from `LibP2PSignedKeyDER.encode`).
    ///   - serial16: 16 serial bytes; the caller must clear the high bit (`serial16[0] &= 0x7F`).
    ///   - notBefore: notBefore as Unix epoch seconds.
    ///   - notAfter: notAfter as Unix epoch seconds.
    ///   - signFn: P-256 ECDSA-SHA256 over the TBS bytes -> DER ECDSA signature.
    ///     Generic over its thrown error type `E` so the call stays typed-throws
    ///     (Embedded-clean: no untyped `throws`/`rethrows`).
    /// - Returns: The DER-encoded certificate.
    public static func buildSelfSignedCert<E: Error>(
        spkiDER: [UInt8],
        signedKeyExtension: [UInt8],
        serial16: [UInt8],
        notBefore: Int64,
        notAfter: Int64,
        signFn: (_ tbs: [UInt8]) throws(E) -> [UInt8]
    ) throws(E) -> [UInt8] {

        // version [0] EXPLICIT { INTEGER 2 } (v3)
        let version = DERWriter.encode(.context0, DERWriter.encodeInteger([0x02]))

        // serialNumber INTEGER (sign-safe minimization; caller cleared high bit)
        let serial = DERWriter.encodeInteger(serial16)

        // signature AlgorithmIdentifier { ecdsa-with-SHA256 }
        let sigAlg = DERWriter.sequence([DERWriter.encodeOID(.ecdsaSHA256)])

        // issuer / subject Name = EMPTY SEQUENCE (30 00)
        let emptyName = DERWriter.sequence([])

        // validity SEQUENCE { UTCTime notBefore, UTCTime notAfter }
        var validityWriter = DERWriter()
        validityWriter.appendUTCTime(epochSeconds: notBefore)
        validityWriter.appendUTCTime(epochSeconds: notAfter)
        let validity = DERWriter.sequence([validityWriter.finish()])

        // Extension { OID libp2pExt, BOOLEAN critical TRUE, OCTET STRING SignedKey }
        // ASN1Builder.x509Extension order: oid ++ [critical?] ++ octetString(value).
        var extContent = [UInt8]()
        extContent.append(contentsOf: DERWriter.encodeOID(.libp2pExt))
        extContent.append(contentsOf: DERWriter.encodeBoolean(true))
        extContent.append(contentsOf: DERWriter.encodeOctetString(signedKeyExtension))
        let extOne = DERWriter.sequence([extContent])

        // extensions [3] EXPLICIT { SEQUENCE { Extension } }
        let exts = DERWriter.encode(.context3, DERWriter.sequence([extOne]))

        // TBSCertificate
        let tbs = DERWriter.sequence([
            version,
            serial,
            sigAlg,
            emptyName,   // issuer
            validity,
            emptyName,   // subject
            spkiDER,
            exts,
        ])

        // Sign + assemble Certificate.
        let signature = try signFn(tbs)
        return DERWriter.sequence([
            tbs,
            sigAlg,
            DERWriter.encodeBitString(signature),
        ])
    }

    // MARK: Parse (fast path)

    /// Parses only the leaf SPKI (verbatim) + the libp2p extension value.
    ///
    /// Skips version/serial/sigAlg/issuer/validity/subject, captures the SPKI,
    /// then walks the extensions for the libp2p OID. The outer signature and
    /// signatureAlgorithm are never inspected (libp2p does not need them), so
    /// trailing bytes after the TBS in the outer SEQUENCE are tolerated.
    public static func parseLeaf(_ certDER: [UInt8]) throws(DERError) -> LeafView {
        var outer = DERReader(certDER)

        // Certificate ::= SEQUENCE { TBSCertificate, sigAlg, sigValue }.
        // Descend into the outer SEQUENCE, then into the TBS SEQUENCE. We DO NOT
        // require the outer SEQUENCE to be fully consumed (we skip sig+sigAlg),
        // so read the outer TLV manually rather than via readConstructed.
        let outerTag = outer.peekTag()
        guard outerTag == DERTag.sequence.rawValue else {
            throw DERError.unexpectedTag(found: outerTag ?? 0x00, wanted: DERTag.sequence.rawValue)
        }
        let (_, outerContent) = try outer.readTLV()
        var certBody = DERReader(outerContent)

        var spki = [UInt8]()
        var extensionValue: [UInt8]? = nil

        try certBody.readConstructed(.sequence) { (tbs) throws(DERError) in
            try tbs.skip()                       // [0] version
            try tbs.skip()                       // serialNumber
            try tbs.skip()                       // signature AlgorithmIdentifier
            try tbs.skip()                       // issuer Name
            try tbs.skip()                       // validity
            try tbs.skip()                       // subject Name
            spki = try tbs.captureRawTLV()       // subjectPublicKeyInfo (verbatim)

            // extensions [3] EXPLICIT (OPTIONAL — always present for libp2p)
            if !tbs.isAtEnd {
                extensionValue = try Self.scanExtensions(&tbs)
            }
        }

        return LeafView(spkiDER: spki, libp2pExtensionValue: extensionValue)
    }

    /// Descends `[3] EXPLICIT { SEQUENCE OF Extension }` and returns the value
    /// of the libp2p extension if present.
    private static func scanExtensions(_ tbs: inout DERReader) throws(DERError) -> [UInt8]? {
        var found: [UInt8]? = nil
        try tbs.readConstructed(.context3) { (extWrap) throws(DERError) in
            try extWrap.readConstructed(.sequence) { (extList) throws(DERError) in
                while !extList.isAtEnd {
                    try extList.readConstructed(.sequence) { (ext) throws(DERError) in
                        let oid = try ext.readOID()
                        // critical BOOLEAN DEFAULT FALSE — present only when true.
                        if ext.peekTag() == DERTag.boolean.rawValue {
                            _ = try ext.readBoolean()
                        }
                        let value = try ext.readOctetString()
                        if oid == .libp2pExt {
                            found = value
                        }
                    }
                }
            }
        }
        return found
    }
}
