// SubjectPublicKeyInfoDER.swift
// RFC 5280 §4.1.2.7 / RFC 7250 SubjectPublicKeyInfo codec for the curves the
// libp2p TLS/QUIC/DTLS path and Raw Public Key authentication use: P-256
// (critical libp2p leaf), plus P-384 and Ed25519 for RPK. Byte-identical to
// the reference encoders. Embedded-clean: no Foundation, no `any`.

/// Encodes and parses DER SubjectPublicKeyInfo for P-256, P-384, and Ed25519.
///
/// ```
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm        AlgorithmIdentifier,
///   subjectPublicKey BIT STRING
/// }
/// AlgorithmIdentifier ::= SEQUENCE {
///   algorithm  OBJECT IDENTIFIER,
///   parameters ANY DEFINED BY algorithm OPTIONAL  -- the EC curve OID, or absent for Ed25519
/// }
/// ```
public enum SubjectPublicKeyInfoDER {

    /// The supported public-key curves.
    public enum Curve: Sendable, Equatable {
        case p256
        case p384
        case ed25519
    }

    // MARK: Encode

    /// Encodes a P-256 SPKI from the 65-byte uncompressed point `0x04 || X || Y`.
    public static func encodeP256(uncompressedPoint65 point: [UInt8]) throws(DERError) -> [UInt8] {
        guard point.count == 65, point.first == 0x04 else { throw DERError.valueTooLarge }
        return encodeEC(curveOID: .secp256r1, point: point)
    }

    /// Encodes a P-384 SPKI from the 97-byte uncompressed point `0x04 || X || Y`.
    public static func encodeP384(uncompressedPoint97 point: [UInt8]) throws(DERError) -> [UInt8] {
        guard point.count == 97, point.first == 0x04 else { throw DERError.valueTooLarge }
        return encodeEC(curveOID: .secp384r1, point: point)
    }

    /// Encodes an Ed25519 SPKI from the 32-byte raw key (RFC 8410: no parameters).
    public static func encodeEd25519(rawKey32 key: [UInt8]) throws(DERError) -> [UInt8] {
        guard key.count == 32 else { throw DERError.valueTooLarge }
        let algorithm = DERWriter.sequence([DERWriter.encodeOID(.ed25519)])
        let bitString = DERWriter.encodeBitString(key)
        return DERWriter.sequence([algorithm, bitString])
    }

    /// Shared EC encoder: AlgorithmIdentifier { ecPublicKey, curveOID } + key BIT STRING.
    private static func encodeEC(curveOID: ObjectID, point: [UInt8]) -> [UInt8] {
        let algorithm = DERWriter.sequence([
            DERWriter.encodeOID(.ecPublicKey),
            DERWriter.encodeOID(curveOID),
        ])
        let bitString = DERWriter.encodeBitString(point)
        return DERWriter.sequence([algorithm, bitString])
    }

    // MARK: Parse

    /// A parsed SubjectPublicKeyInfo.
    public struct Parsed: Sendable, Equatable {
        /// The curve identified by the algorithm/parameters OID pair.
        public let curve: Curve
        /// The public-key bytes: 65 (P-256), 97 (P-384), or 32 (Ed25519).
        public let keyBytes: [UInt8]
        /// The verbatim input bytes — the SignedKey verify message uses these exactly.
        public let spkiDER: [UInt8]
    }

    /// Parses an SPKI, walking `SEQUENCE { SEQUENCE { OID [, OID] }, BIT STRING }`
    /// and dispatching on the algorithm/parameters OID pair. Rejects unknown
    /// algorithms/curves with `.unsupportedOID`.
    public static func parse(_ spki: [UInt8]) throws(DERError) -> Parsed {
        var outer = DERReader(spki)
        // Capture algorithm OIDs + key bytes inside the SEQUENCE descent.
        var algorithmOID = ObjectID([])
        var parametersOID: ObjectID? = nil
        var keyBytes = [UInt8]()

        try outer.readConstructed(.sequence) { (top) throws(DERError) in
            try top.readConstructed(.sequence) { (alg) throws(DERError) in
                algorithmOID = try alg.readOID()
                if alg.peekTag() == DERTag.objectIdentifier.rawValue {
                    parametersOID = try alg.readOID()
                }
            }
            keyBytes = try top.readBitString()
        }

        let curve: Curve
        if algorithmOID == .ecPublicKey {
            switch parametersOID {
            case .some(.secp256r1):
                curve = .p256
                guard keyBytes.count == 65 else { throw DERError.valueTooLarge }
            case .some(.secp384r1):
                curve = .p384
                guard keyBytes.count == 97 else { throw DERError.valueTooLarge }
            default:
                throw DERError.unsupportedOID
            }
        } else if algorithmOID == .ed25519 {
            // RFC 8410 §3: Ed25519 must not carry parameters.
            guard parametersOID == nil else { throw DERError.unsupportedOID }
            curve = .ed25519
            guard keyBytes.count == 32 else { throw DERError.valueTooLarge }
        } else {
            throw DERError.unsupportedOID
        }

        return Parsed(curve: curve, keyBytes: keyBytes, spkiDER: spki)
    }
}
