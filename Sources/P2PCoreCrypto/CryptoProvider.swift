// CryptoProvider.swift
// Aggregating seam that the QUIC/TLS stack depends on instead of swift-crypto.
// Embedded-clean: every primitive is an `associatedtype`, never `any`.

/// The single dependency-inversion seam between the QUIC/TLS stack and a concrete
/// cryptography backend.
///
/// All primitives are exposed as `associatedtype`s (20 in total) rather than
/// `any`-typed values, so a generic upper layer (`<C: CryptoProvider>`)
/// specialises cleanly under Embedded Swift. This protocol defines the *contract*
/// only; concrete providers (a swift-crypto-backed host one and an Embedded one)
/// arrive in M4.
public protocol CryptoProvider: Sendable {
    // AEAD constructions (QUIC/TLS1.3 mandatory suites)
    associatedtype AESGCM128:  AEAD
    associatedtype AESGCM256:  AEAD
    associatedtype ChaChaPoly: AEAD

    // Hashes
    associatedtype SHA256: HashFunction
    associatedtype SHA384: HashFunction

    // Key derivation, hash-bound by same-type constraints (A7)
    associatedtype HKDFSHA256: KeyDerivation where HKDFSHA256.Hash == SHA256
    associatedtype HKDFSHA384: KeyDerivation where HKDFSHA384.Hash == SHA384

    // Message authentication (STUN = SHA1; QUIC/TLS/Noise = SHA256/384)
    associatedtype HMACSHA1:   MessageAuthenticationCode
    associatedtype HMACSHA256: MessageAuthenticationCode
    associatedtype HMACSHA384: MessageAuthenticationCode

    // Key agreement
    associatedtype X25519:        KeyAgreement
    associatedtype P256Agreement: KeyAgreement
    associatedtype P384Agreement: KeyAgreement

    // Signatures
    associatedtype Ed25519:       SignatureScheme
    associatedtype P256Signature: SignatureScheme
    associatedtype P384Signature: SignatureScheme

    // Ambient capabilities
    associatedtype Random:          RandomSource
    associatedtype Clock:           MonotonicClock
    associatedtype HeaderProtection: HeaderProtectionProvider

    // AEADs are keyed factories (one value per derived key).
    static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> AESGCM128  // key 16
    static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> AESGCM256  // key 32
    static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> ChaChaPoly // key 32

    // Ambient singletons (no provider instance state; static for trivial specialization)
    static var random: Random { get }
    static var clock:  Clock  { get }
}
