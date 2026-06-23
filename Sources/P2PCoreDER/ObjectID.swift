// ObjectID.swift
// An OBJECT IDENTIFIER as its DER *content* octets (after tag+length). We only
// ever compare OIDs, never decode their sub-identifiers into integers, so there
// is no overflow path and no dotted-string parse. Embedded-clean.

/// An OBJECT IDENTIFIER represented by its DER content octets.
///
/// O(1) value comparison against the fixed constants below; no registry, no
/// dotted-string parsing, no sub-identifier integer decode (so no overflow
/// case exists). The content bytes are exactly what appears after the
/// `0x06 <len>` header on the wire.
public struct ObjectID: Equatable, Sendable {

    /// The OID *content* octets (the bytes after `0x06 <len>`).
    public let der: [UInt8]

    /// Wraps raw OID content octets.
    @inlinable public init(_ der: [UInt8]) {
        self.der = der
    }

    // MARK: Fixed constants (content octets, cross-checked vs ASN1Builder.oid)

    /// id-ecPublicKey — `1.2.840.10045.2.1`.
    public static let ecPublicKey = ObjectID([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])

    /// secp256r1 / prime256v1 — `1.2.840.10045.3.1.7`.
    public static let secp256r1 = ObjectID([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])

    /// secp384r1 — `1.3.132.0.34`.
    public static let secp384r1 = ObjectID([0x2B, 0x81, 0x04, 0x00, 0x22])

    /// ecdsa-with-SHA256 — `1.2.840.10045.4.3.2`.
    public static let ecdsaSHA256 = ObjectID([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])

    /// id-Ed25519 — `1.3.101.112`.
    public static let ed25519 = ObjectID([0x2B, 0x65, 0x70])

    /// The libp2p extension OID — `1.3.6.1.4.1.53594.1.1`.
    ///
    /// `53594 = 0xD15A`, base-128 with continuation bits = `0x83 0xA2 0x5A`
    /// (the corrected encoding; an earlier design doc wrongly used `0x83 0x9A 0x1A`).
    public static let libp2pExt = ObjectID([0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01])
}
