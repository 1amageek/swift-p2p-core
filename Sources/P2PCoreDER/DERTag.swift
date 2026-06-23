// DERTag.swift
// The closed set of ASN.1 identifier octets the libp2p TLS/QUIC/DTLS cert path
// touches. Short-form tag numbers only; no long-form, no SET, no NULL, no
// string types, no other context tags. Embedded-clean: no Foundation, no `any`.

/// The identifier octets used on the libp2p certificate path.
///
/// Each case is the full DER identifier octet (class + constructed bit + tag
/// number), not just the tag number. The universe is deliberately small: the
/// libp2p self-signed cert + SignedKey extension + SubjectPublicKeyInfo only
/// ever use these tags. `NULL` is intentionally absent (the ecPublicKey
/// AlgorithmIdentifier carries the curve OID as `parameters`, never NULL;
/// Ed25519 omits parameters entirely).
public enum DERTag: UInt8, Sendable {
    /// BOOLEAN (DER true == 0xFF).
    case boolean = 0x01

    /// INTEGER.
    case integer = 0x02

    /// BIT STRING (content is `[unusedBits, ...]`).
    case bitString = 0x03

    /// OCTET STRING.
    case octetString = 0x04

    /// OBJECT IDENTIFIER.
    case objectIdentifier = 0x06

    /// UTCTime — write-only (`"yyMMddHHmmssZ"`).
    case utcTime = 0x17

    /// GeneralizedTime — write-only, used iff year >= 2050.
    case generalizedTime = 0x18

    /// SEQUENCE (`0x10` universal | `0x20` constructed).
    case sequence = 0x30

    /// `[0]` EXPLICIT constructed — TBS version.
    case context0 = 0xA0

    /// `[3]` EXPLICIT constructed — TBS extensions.
    case context3 = 0xA3
}
