// SignatureProvider.swift
// Capability protocol: the digital-signature schemes a provider must supply
// (Ed25519, ECDSA P-256, ECDSA P-384). Embedded-clean: every primitive is an
// `associatedtype`.

/// The signature capability of a crypto backend.
public protocol SignatureProvider: Sendable {
    // Signatures
    associatedtype Ed25519:       SignatureScheme
    associatedtype P256Signature: SignatureScheme
    associatedtype P384Signature: SignatureScheme
}
