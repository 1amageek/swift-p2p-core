// LibP2PSignedKeyDER.swift
// The libp2p SignedKey extension value codec — byte-identical to the reference
// LibP2PCertificate.encodeSignedKey / LibP2PCertificateHelper.encodeSignedKey.
// Embedded-clean: no Foundation, no `any`.

/// Encodes and parses the libp2p SignedKey extension value.
///
/// ```
/// SignedKey ::= SEQUENCE {
///   publicKey OCTET STRING,   -- protobuf-encoded libp2p PublicKey
///   signature OCTET STRING    -- identityKey.sign("libp2p-tls-handshake:" || SPKI_DER)
/// }
/// ```
public enum LibP2PSignedKeyDER {

    /// Encodes the SignedKey from the protobuf public key + signature bytes.
    public static func encode(protobufPubKey: [UInt8], signature: [UInt8]) -> [UInt8] {
        DERWriter.sequence([
            DERWriter.encodeOctetString(protobufPubKey),
            DERWriter.encodeOctetString(signature),
        ])
    }

    /// Parses the SignedKey into its two OCTET STRINGs. Requires at least two
    /// children; any trailing children are ignored (matching the reference's
    /// `children.count >= 2`).
    public static func parse(_ value: [UInt8]) throws(DERError) -> (protobufPubKey: [UInt8], signature: [UInt8]) {
        var reader = DERReader(value)
        var pub = [UInt8]()
        var sig = [UInt8]()

        let found = reader.peekTag()
        guard found == DERTag.sequence.rawValue else {
            throw DERError.unexpectedTag(found: found ?? 0x00, wanted: DERTag.sequence.rawValue)
        }
        // Descend into the SEQUENCE but tolerate extra trailing children, so we
        // do not use readConstructed's full-consumption requirement here.
        let (_, content) = try reader.readTLV()
        var inner = DERReader(content)
        pub = try inner.readOctetString()
        sig = try inner.readOctetString()
        return (pub, sig)
    }
}
