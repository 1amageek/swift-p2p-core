import P2PCoreCrypto
import SSLCrypto

/// Compatibility names for the canonical `swift-ssl` backend.
///
/// The provider surface remains owned by `P2PCoreCrypto`; all primitive
/// implementations below are sourced from `SSLCrypto` and contain no
/// `swift-crypto` or BoringSSL dependency.
public typealias DefaultSHA256 = SSLBackendSHA256
public typealias DefaultSHA384 = SSLBackendSHA384
public typealias DefaultHMACSHA1 = SSLBackendHMACSHA1
public typealias DefaultHMACSHA256 = SSLBackendHMACSHA256
public typealias DefaultHMACSHA384 = SSLBackendHMACSHA384
public typealias DefaultHKDFSHA256 = SSLBackendHKDFSHA256
public typealias DefaultHKDFSHA384 = SSLBackendHKDFSHA384
public typealias DefaultX25519 = SSLBackendX25519
public typealias DefaultP256Agreement = SSLBackendP256Agreement
    public typealias DefaultP384Agreement = SSLBackendP384Agreement
public typealias DefaultEd25519 = SSLBackendEd25519
public typealias DefaultP256Signature = SSLBackendP256Signature
public typealias DefaultRawP256Signature = SSLBackendRawP256Signature
    public typealias DefaultP384Signature = SSLBackendP384Signature
public typealias DefaultRandom = SSLBackendRandom
public typealias DefaultMonotonicClock = SSLBackendClock
public typealias DefaultHeaderProtection = SSLBackendHeaderProtection

/// The historical algorithm-selecting AEAD façade over the canonical
/// algorithm-specific `swift-ssl` implementations.
public struct DefaultAEAD: AEAD {
    public enum Algorithm: Sendable {
        case aes128gcm
        case aes256gcm
        case chacha20poly1305
    }

    private enum Storage: Sendable {
        case aes(SSLBackendAESGCM)
        case chacha(SSLBackendChaChaPoly)
    }

    private let storage: Storage

    public static let nonceLength = 12
    public static let tagLength = 16

    public init(algorithm: Algorithm, key: Span<UInt8>) throws(CryptoError) {
        switch algorithm {
        case .aes128gcm, .aes256gcm:
            storage = .aes(try SSLBackendAESGCM(key: key))
        case .chacha20poly1305:
            storage = .chacha(try SSLBackendChaChaPoly(key: key))
        }
    }

    public func seal(
        _ plaintext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(CryptoError) -> [UInt8] {
        switch storage {
        case .aes(let cipher):
            return try cipher.seal(plaintext, nonce: nonce, aad: aad)
        case .chacha(let cipher):
            return try cipher.seal(plaintext, nonce: nonce, aad: aad)
        }
    }

    public func open(
        _ ciphertext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(CryptoError) -> [UInt8] {
        switch storage {
        case .aes(let cipher):
            return try cipher.open(ciphertext, nonce: nonce, aad: aad)
        case .chacha(let cipher):
            return try cipher.open(ciphertext, nonce: nonce, aad: aad)
        }
    }
}

/// Reusable AES-128-CTR context for SRTP and other packet protocols.
public final class DefaultAES128CounterMode: AESCounterModeCipher, Sendable {
    private let cipher: AES128CounterMode

    public init(key: Span<UInt8>) throws(AESCounterModeError) {
        do {
            cipher = try AES128CounterMode(key: key)
        } catch let error {
            switch error {
            case .invalidLength(let expected, let actual):
                throw .invalidKeyLength(expected: expected, actual: actual)
            default:
                throw .providerFailure
            }
        }
    }

    public func applyKeystream(
        to bytes: inout [UInt8],
        range: Range<Int>,
        initialCounter: Span<UInt8>
    ) throws(AESCounterModeError) {
        do {
            try cipher.applyKeystream(
                to: &bytes,
                range: range,
                initialCounter: initialCounter
            )
        } catch let error {
            switch error {
            case .invalidLength(_, let actual):
                throw .invalidCounterLength(expected: 16, actual: actual)
            case .invalidRange:
                throw .invalidRange(
                    lowerBound: range.lowerBound,
                    upperBound: range.upperBound,
                    bufferCount: bytes.count
                )
            default:
                throw .providerFailure
            }
        }
    }
}

/// Aggregates the pure Swift `swift-ssl` primitives behind the existing
/// capability protocols used by QUIC, Noise, STUN, and SRTP.
public enum DefaultCryptoProvider: CryptoProvider {
    public typealias AESGCM128 = SSLBackendAESGCM
    public typealias AESGCM256 = SSLBackendAESGCM
    public typealias ChaChaPoly = SSLBackendChaChaPoly
    public typealias SHA256 = SSLBackendSHA256
    public typealias SHA384 = SSLBackendSHA384
    public typealias HKDFSHA256 = SSLBackendHKDFSHA256
    public typealias HKDFSHA384 = SSLBackendHKDFSHA384
    public typealias HMACSHA1 = SSLBackendHMACSHA1
    public typealias HMACSHA256 = SSLBackendHMACSHA256
    public typealias HMACSHA384 = SSLBackendHMACSHA384
    public typealias X25519 = SSLBackendX25519
    public typealias P256Agreement = SSLBackendP256Agreement
    public typealias P384Agreement = SSLBackendP384Agreement
    public typealias Ed25519 = SSLBackendEd25519
    public typealias P256Signature = SSLBackendP256Signature
    public typealias P384Signature = SSLBackendP384Signature
    public typealias RawP256Signature = SSLBackendRawP256Signature
    public typealias RawP384Signature = SSLBackendRawP384Signature
    public typealias Random = SSLBackendRandom
    public typealias Clock = SSLBackendClock
    public typealias HeaderProtection = SSLBackendHeaderProtection

    public static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> SSLBackendAESGCM {
        try SSLBackendAESGCM(key: key)
    }

    public static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> SSLBackendAESGCM {
        try SSLBackendAESGCM(key: key)
    }

    public static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> SSLBackendChaChaPoly {
        try SSLBackendChaChaPoly(key: key)
    }

    public static let random = SSLBackendRandom()
    public static let clock = SSLBackendClock()
}

extension DefaultCryptoProvider: AESCounterModeProvider {
    public typealias AES128CounterMode = DefaultAES128CounterMode
}
