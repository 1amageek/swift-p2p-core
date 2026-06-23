// DERError.swift
// Typed errors for strict-DER reading/writing. Embedded-clean: no Foundation,
// no `any`, no String payloads (closed-for-Embedded enum). Every malformed-wire
// condition is a distinct case propagated to the caller; never a silent fallback.

/// Errors raised by ``DERReader`` and ``DERWriter`` on malformed or out-of-range
/// DER input. The reader is strict (rejects BER indefinite length, non-minimal
/// lengths, trailing garbage) because this is security-sensitive certificate
/// parsing where both ends of the wire are controlled (libp2p peers).
public enum DERError: Error, Equatable, Sendable {
    /// A read ran past the end of the buffer.
    case truncated

    /// The encoded length cannot be represented as an `Int`, or its declared
    /// extent exceeds the view.
    case badLength

    /// A `0x80` (indefinite) length octet — illegal in DER.
    case indefiniteLength

    /// Long form used where short form suffices, or a leading `0x00` length octet.
    case nonMinimalLength

    /// A tag did not match the one required at this position.
    case unexpectedTag(found: UInt8, wanted: UInt8)

    /// A BIT STRING declared non-zero unused (padding) bits.
    case nonZeroBitStringPadding(UInt8)

    /// A BIT STRING had no leading unused-bits octet (empty content).
    case bitStringEmpty

    /// A constructed body was descended into but not fully consumed.
    case trailingBytes

    /// An INTEGER had zero content octets.
    case integerEmpty

    /// A declared length is implausible for the target buffer.
    case valueTooLarge

    /// A BOOLEAN had a content length other than one octet.
    case malformedBoolean

    /// A recognized structure carried an OID the codec does not accept
    /// (e.g. an unsupported curve / algorithm in SubjectPublicKeyInfo).
    case unsupportedOID
}
