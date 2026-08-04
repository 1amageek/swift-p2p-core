// Pure Swift backend for the DTLS/TLS core.
//
// This file is the only bridge between the generic P2P crypto protocols and
// swift-ssl.  It deliberately keeps the core protocols intact: the handshake
// FSM depends on capabilities, while the concrete implementation is supplied
// by SSLCore/SSLCrypto.  The bridge owns byte values at each protocol boundary;
// no C crypto object or Foundation value crosses into the engine.

import SSLCore
import SSLCrypto
import P2PCoreCrypto
import P2PCoreDER

@inline(__always)
private func copyBytes(_ bytes: Span<UInt8>) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: bytes.count)
    var index = 0
    while index < bytes.count {
        result[index] = bytes[index]
        index += 1
    }
    return result
}

private enum SSLBackendMap {
    static func primitiveFailure() -> CryptoError { .providerFailure }
    static func invalidLength(expected: Int, actual: Int) -> CryptoError {
        .invalidLength(expected: expected, actual: actual)
    }
}

// MARK: Hashes

public struct SSLBackendSHA256: P2PCoreCrypto.HashFunction {
    public static let digestLength = 32
    public static let blockLength = 64
    private var input: [UInt8] = []

    public init() {}

    public mutating func update(_ data: Span<UInt8>) {
        input.append(contentsOf: copyBytes(data))
    }

    public consuming func finalize() -> [UInt8] {
        var output = [UInt8](repeating: 0, count: SHA256.digestByteCount)
        do {
            var destination = output.mutableSpan
            try SHA256.hash(input.span, into: &destination)
        } catch {
            preconditionFailure("swift-ssl SHA-256 finalization failed")
        }
        return output
    }
}

public struct SSLBackendSHA384: P2PCoreCrypto.HashFunction {
    public static let digestLength = 48
    public static let blockLength = 128
    private var input: [UInt8] = []

    public init() {}

    public mutating func update(_ data: Span<UInt8>) {
        input.append(contentsOf: copyBytes(data))
    }

    public consuming func finalize() -> [UInt8] {
        var output = [UInt8](repeating: 0, count: SHA384.digestByteCount)
        do {
            var destination = output.mutableSpan
            try SHA384.hash(input.span, into: &destination)
        } catch {
            preconditionFailure("swift-ssl SHA-384 finalization failed")
        }
        return output
    }
}

// MARK: HMAC

private enum SSLHMACSupport {
    static func sha256(message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: HMACSHA256.tagByteCount)
        do {
            var destination = output.mutableSpan
            try HMACSHA256.authenticate(message, using: key, into: &destination)
        } catch {
            preconditionFailure("swift-ssl HMAC-SHA-256 finalization failed")
        }
        return output
    }

    static func sha384(message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: HMACSHA384.tagByteCount)
        do {
            var destination = output.mutableSpan
            try HMACSHA384.authenticate(message, using: key, into: &destination)
        } catch {
            preconditionFailure("swift-ssl HMAC-SHA-384 finalization failed")
        }
        return output
    }
}

public struct SSLBackendHMACSHA256: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 32
    private let key: [UInt8]
    private var message: [UInt8] = []

    public init(key: Span<UInt8>) { self.key = copyBytes(key) }
    public mutating func update(_ data: Span<UInt8>) { message.append(contentsOf: copyBytes(data)) }
    public consuming func finalize() -> [UInt8] { SSLHMACSupport.sha256(message: message.span, key: key.span) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        SSLHMACSupport.sha256(message: message, key: key)
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        let expected = authenticationCode(for: message, key: key)
        guard expected.count == mac.count else { return false }
        var different: UInt8 = 0
        var index = 0
        while index < mac.count { different |= mac[index] ^ expected[index]; index += 1 }
        return different == 0
    }
}

public struct SSLBackendHMACSHA384: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 48
    private let key: [UInt8]
    private var message: [UInt8] = []

    public init(key: Span<UInt8>) { self.key = copyBytes(key) }
    public mutating func update(_ data: Span<UInt8>) { message.append(contentsOf: copyBytes(data)) }
    public consuming func finalize() -> [UInt8] { SSLHMACSupport.sha384(message: message.span, key: key.span) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        SSLHMACSupport.sha384(message: message, key: key)
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        let expected = authenticationCode(for: message, key: key)
        guard expected.count == mac.count else { return false }
        var different: UInt8 = 0
        var index = 0
        while index < mac.count { different |= mac[index] ^ expected[index]; index += 1 }
        return different == 0
    }
}

// DTLS cookies historically use HMAC-SHA1 in some deployments.  The DTLS
// engine in this package uses SHA-256 cookies, but the provider still exposes
// the protocol's SHA-1 slot.  It is implemented as a strict, local SHA-1 HMAC
// rather than a fake alias, so selecting it cannot silently change semantics.
public struct SSLBackendHMACSHA1: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 20
    private let key: [UInt8]
    private var message: [UInt8] = []
    public init(key: Span<UInt8>) { self.key = copyBytes(key) }
    public mutating func update(_ data: Span<UInt8>) { message.append(contentsOf: copyBytes(data)) }
    public consuming func finalize() -> [UInt8] { SHA1Core.hmac(message: message, key: key) }
    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        SHA1Core.hmac(message: copyBytes(message), key: copyBytes(key))
    }
    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        let expected = authenticationCode(for: message, key: key)
        guard expected.count == mac.count else { return false }
        var different: UInt8 = 0
        var index = 0
        while index < mac.count { different |= mac[index] ^ expected[index]; index += 1 }
        return different == 0
    }
}

// Small SHA-1 implementation used solely for the protocol-required HMAC slot.
// It is kept private to the adapter; TLS/DTLS traffic uses SHA-256/384.
private enum SHA1Core {
    static func hmac(message: [UInt8], key: [UInt8]) -> [UInt8] {
        var normalized = key
        if normalized.count > 64 { normalized = digest(normalized) }
        normalized += [UInt8](repeating: 0, count: 64 - normalized.count)
        var inner = [UInt8](repeating: 0x36, count: 64)
        var outer = [UInt8](repeating: 0x5c, count: 64)
        for index in 0..<64 { inner[index] ^= normalized[index]; outer[index] ^= normalized[index] }
        inner.append(contentsOf: message)
        outer.append(contentsOf: digest(inner))
        return digest(outer)
    }

    static func digest(_ input: [UInt8]) -> [UInt8] {
        var bytes = input
        bytes.append(0x80)
        while bytes.count % 64 != 56 { bytes.append(0) }
        let bitCount = UInt64(input.count) &* 8
        for shift in stride(from: 56, through: 0, by: -8) { bytes.append(UInt8(truncatingIfNeeded: bitCount >> UInt64(shift))) }
        var h: [UInt32] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        var offset = 0
        while offset < bytes.count {
            var w = [UInt32](repeating: 0, count: 80)
            for index in 0..<16 {
                let base = offset + index * 4
                w[index] = UInt32(bytes[base]) << 24 | UInt32(bytes[base + 1]) << 16 | UInt32(bytes[base + 2]) << 8 | UInt32(bytes[base + 3])
            }
            for index in 16..<80 { w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotateLeft(1) }
            var (a, b, c, d, e) = (h[0], h[1], h[2], h[3], h[4])
            for index in 0..<80 {
                let (f, k): (UInt32, UInt32)
                switch index {
                case 0..<20: f = (b & c) | ((~b) & d); k = 0x5A827999
                case 20..<40: f = b ^ c ^ d; k = 0x6ED9EBA1
                case 40..<60: f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
                default: f = b ^ c ^ d; k = 0xCA62C1D6
                }
                let next = a.rotateLeft(5) &+ f &+ e &+ k &+ w[index]
                e = d; d = c; c = b.rotateLeft(30); b = a; a = next
            }
            h[0] &+= a; h[1] &+= b; h[2] &+= c; h[3] &+= d; h[4] &+= e
            offset += 64
        }
        var result = [UInt8](); result.reserveCapacity(20)
        for word in h {
            result += [
                UInt8(truncatingIfNeeded: word >> 24),
                UInt8(truncatingIfNeeded: word >> 16),
                UInt8(truncatingIfNeeded: word >> 8),
                UInt8(truncatingIfNeeded: word),
            ]
        }
        return result
    }
}

private extension UInt32 {
    func rotateLeft(_ count: UInt32) -> UInt32 { (self << count) | (self >> (32 - count)) }
}

// MARK: HKDF

public struct SSLBackendHKDFSHA256: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = SSLBackendSHA256
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 32)
        do { var destination = output.mutableSpan; try HKDFSHA256.extract(inputKeyMaterial: ikm, salt: salt, into: &destination) } catch { preconditionFailure("swift-ssl HKDF-SHA-256 extraction failed") }
        return output
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(CryptoError) -> [UInt8] {
        guard length >= 0, length <= 255 * 32 else { throw .invalidLength(expected: 255 * 32, actual: length) }
        var output = [UInt8](repeating: 0, count: length)
        do { var destination = output.mutableSpan; try HKDFSHA256.expand(pseudorandomKey: prk, info: info, into: &destination) }
        catch { throw .providerFailure }
        return output
    }
}

public struct SSLBackendHKDFSHA384: P2PCoreCrypto.KeyDerivation {
    public typealias Hash = SSLBackendSHA384
    public init() {}
    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 48)
        do { var destination = output.mutableSpan; try HKDFSHA384.extract(inputKeyMaterial: ikm, salt: salt, into: &destination) } catch { preconditionFailure("swift-ssl HKDF-SHA-384 extraction failed") }
        return output
    }
    public func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(CryptoError) -> [UInt8] {
        guard length >= 0, length <= 255 * 48 else { throw .invalidLength(expected: 255 * 48, actual: length) }
        var output = [UInt8](repeating: 0, count: length)
        do { var destination = output.mutableSpan; try HKDFSHA384.expand(pseudorandomKey: prk, info: info, into: &destination) }
        catch { throw .providerFailure }
        return output
    }
}

// MARK: AEAD

private protocol SSLBackendAEAD: P2PCoreCrypto.AEAD {
    static var keyByteCount: Int { get }
    init(key: Span<UInt8>) throws(CryptoError)
}

public struct SSLBackendAESGCM: SSLBackendAEAD {
    public static let nonceLength = 12
    public static let tagLength = 16
    public static var keyByteCount: Int { 16 }
    private let key: [UInt8]
    public init(key: Span<UInt8>) throws(CryptoError) { guard key.count == 16 || key.count == 32 else { throw .invalidLength(expected: 16, actual: key.count) }; self.key = copyBytes(key) }
    public func seal(_ plaintext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: plaintext.count + 16)
        do { let cipher = try AESGCM(key: key.span); var destination = output.mutableSpan; try cipher.seal(plaintext: plaintext, authenticatedData: aad, nonce: nonce, into: &destination) }
        catch { throw .providerFailure }
        return output
    }
    public func open(_ ciphertext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        guard ciphertext.count >= 16 else { throw .invalidLength(expected: 16, actual: ciphertext.count) }
        var output = [UInt8](repeating: 0, count: ciphertext.count - 16)
        do { let cipher = try AESGCM(key: key.span); var destination = output.mutableSpan; try cipher.open(ciphertextAndTag: ciphertext, authenticatedData: aad, nonce: nonce, into: &destination) }
        catch { throw .authenticationFailure }
        return output
    }
}

public struct SSLBackendChaChaPoly: SSLBackendAEAD {
    public static let nonceLength = 12
    public static let tagLength = 16
    public static let keyByteCount = 32
    private let key: [UInt8]
    public init(key: Span<UInt8>) throws(CryptoError) { guard key.count == 32 else { throw .invalidLength(expected: 32, actual: key.count) }; self.key = copyBytes(key) }
    public func seal(_ plaintext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: plaintext.count + 16)
        do { let cipher = try ChaCha20Poly1305(key: key.span); var destination = output.mutableSpan; try cipher.seal(plaintext: plaintext, authenticatedData: aad, nonce: nonce, into: &destination) }
        catch { throw .providerFailure }
        return output
    }
    public func open(_ ciphertext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        guard ciphertext.count >= 16 else { throw .invalidLength(expected: 16, actual: ciphertext.count) }
        var output = [UInt8](repeating: 0, count: ciphertext.count - 16)
        do { let cipher = try ChaCha20Poly1305(key: key.span); var destination = output.mutableSpan; try cipher.open(ciphertextAndTag: ciphertext, authenticatedData: aad, nonce: nonce, into: &destination) }
        catch { throw .authenticationFailure }
        return output
    }
}

// MARK: Key agreement

public enum SSLBackendX25519: P2PCoreCrypto.KeyAgreement {
    public struct PrivateKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct PublicKey: Sendable { fileprivate let bytes: [UInt8] }
    public static func generatePrivateKey() throws(CryptoError) -> PrivateKey {
        do { let key = try X25519PrivateKey.generate(); return key.withBorrowedBytes { PrivateKey(bytes: copyBytes($0)) } } catch { throw .providerFailure }
    }
    public static func privateKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PrivateKey { guard rawRepresentation.count == 32 else { throw .invalidLength(expected: 32, actual: rawRepresentation.count) }; do { _ = try X25519PrivateKey(bytes: rawRepresentation) } catch { throw .invalidKeyMaterial }; return PrivateKey(bytes: copyBytes(rawRepresentation)) }
    public static func publicKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PublicKey { guard rawRepresentation.count == 32 else { throw .invalidLength(expected: 32, actual: rawRepresentation.count) }; do { _ = try X25519PublicKey(bytes: rawRepresentation) } catch { throw .invalidKeyMaterial }; return PublicKey(bytes: copyBytes(rawRepresentation)) }
    public static func publicKey(for privateKey: PrivateKey) -> PublicKey { do { let key = try X25519PrivateKey(bytes: privateKey.bytes.span); return PublicKey(bytes: key.publicKey().withBorrowedBytes { copyBytes($0) }) } catch { preconditionFailure("swift-ssl X25519 public-key derivation failed") } }
    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] { privateKey.bytes }
    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] { publicKey.bytes }
    public static func sharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey) throws(CryptoError) -> [UInt8] { do { let privateKey = try X25519PrivateKey(bytes: privateKey.bytes.span); let publicKey = try X25519PublicKey(bytes: peerPublicKey.bytes.span); let secret = try X25519.sharedSecret(privateKey: privateKey, peerPublicKey: publicKey); return secret.withBorrowedBytes { copyBytes($0) } } catch { throw .keyAgreementFailure } }
}

public enum SSLBackendP256Agreement: P2PCoreCrypto.KeyAgreement {
    public struct PrivateKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct PublicKey: Sendable { fileprivate let bytes: [UInt8] }
    public static func generatePrivateKey() throws(CryptoError) -> PrivateKey { let bytes = SSLBackendRandom().randomBytes(32); do { _ = try P256PrivateKey(bytes: bytes.span); return PrivateKey(bytes: bytes) } catch { throw .providerFailure } }
    public static func privateKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PrivateKey { guard rawRepresentation.count == 32 else { throw .invalidLength(expected: 32, actual: rawRepresentation.count) }; do { _ = try P256PrivateKey(bytes: rawRepresentation) } catch { throw .invalidKeyMaterial }; return PrivateKey(bytes: copyBytes(rawRepresentation)) }
    public static func publicKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PublicKey { guard rawRepresentation.count == 65 else { throw .invalidLength(expected: 65, actual: rawRepresentation.count) }; do { _ = try P256PublicKey(bytes: rawRepresentation) } catch { throw .invalidKeyMaterial }; return PublicKey(bytes: copyBytes(rawRepresentation)) }
    public static func publicKey(for privateKey: PrivateKey) -> PublicKey { do { let key = try P256PrivateKey(bytes: privateKey.bytes.span); return PublicKey(bytes: copyBytes(key.publicKey().span)) } catch { preconditionFailure("swift-ssl P-256 public-key derivation failed") } }
    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] { privateKey.bytes }
    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] { publicKey.bytes }
    public static func sharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey) throws(CryptoError) -> [UInt8] { do { let privateKey = try P256PrivateKey(bytes: privateKey.bytes.span); let publicKey = try P256PublicKey(bytes: peerPublicKey.bytes.span); let secret = try P256KeyAgreement.sharedSecret(privateKey: privateKey, peerPublicKey: publicKey); return secret.withBorrowedBytes { copyBytes($0) } } catch { throw .keyAgreementFailure } }
}

/// P-384 ECDH backed by the canonical `swift-ssl` implementation.
///
/// The provider stores only owned raw bytes at the P2P boundary. The
/// `P384PrivateKey`/`P384PublicKey` owners are reconstructed inside each
/// operation and all borrowed spans are scoped to that operation.
public enum SSLBackendP384Agreement: P2PCoreCrypto.KeyAgreement {
    public struct PrivateKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct PublicKey: Sendable { fileprivate let bytes: [UInt8] }

    public static func generatePrivateKey() throws(CryptoError) -> PrivateKey {
        do {
            let key = try P384PrivateKey.generate()
            return key.withBorrowedBytes { PrivateKey(bytes: copyBytes($0)) }
        } catch {
            throw .providerFailure
        }
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PrivateKey {
        guard rawRepresentation.count == P384PrivateKey.byteCount else {
            throw .invalidLength(expected: P384PrivateKey.byteCount, actual: rawRepresentation.count)
        }
        do {
            _ = try P384PrivateKey(bytes: rawRepresentation)
        } catch {
            throw .invalidKeyMaterial
        }
        return PrivateKey(bytes: copyBytes(rawRepresentation))
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PublicKey {
        guard rawRepresentation.count == P384PublicKey.uncompressedByteCount else {
            throw .invalidLength(
                expected: P384PublicKey.uncompressedByteCount,
                actual: rawRepresentation.count
            )
        }
        do {
            _ = try P384PublicKey(bytes: rawRepresentation)
        } catch {
            throw .invalidKeyMaterial
        }
        return PublicKey(bytes: copyBytes(rawRepresentation))
    }

    public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        do {
            let key = try P384PrivateKey(bytes: privateKey.bytes.span)
            return PublicKey(bytes: copyBytes(key.publicKey().span))
        } catch {
            preconditionFailure("swift-ssl P-384 public-key derivation failed")
        }
    }

    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
        privateKey.bytes
    }

    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
        publicKey.bytes
    }

    public static func sharedSecret(
        privateKey: PrivateKey,
        peerPublicKey: PublicKey
    ) throws(CryptoError) -> [UInt8] {
        do {
            let privateKey = try P384PrivateKey(bytes: privateKey.bytes.span)
            let publicKey = try P384PublicKey(bytes: peerPublicKey.bytes.span)
            let secret = try P384KeyAgreement.sharedSecret(
                privateKey: privateKey,
                peerPublicKey: publicKey
            )
            return secret.withBorrowedBytes { copyBytes($0) }
        } catch {
            throw .keyAgreementFailure
        }
    }
}

// MARK: Signatures

public enum SSLBackendEd25519: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct VerifyingKey: Sendable { fileprivate let bytes: [UInt8] }
    public static func generateSigningKey() throws(CryptoError) -> SigningKey { var seed = [UInt8](repeating: 0, count: 32); do { var destination = seed.mutableSpan; try SystemEntropySource().fill(&destination); _ = try Ed25519PrivateKey(seed: seed.span); return SigningKey(bytes: copyBytes(seed.span)) } catch { throw .providerFailure } }
    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey { guard rawRepresentation.count == 32 else { throw .invalidLength(expected: 32, actual: rawRepresentation.count) }; do { _ = try Ed25519PrivateKey(seed: rawRepresentation) } catch { throw .invalidKeyMaterial }; return SigningKey(bytes: copyBytes(rawRepresentation)) }
    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey { guard rawRepresentation.count == 32 else { throw .invalidLength(expected: 32, actual: rawRepresentation.count) }; do { _ = try Ed25519PublicKey(bytes: rawRepresentation) } catch { throw .invalidKeyMaterial }; return VerifyingKey(bytes: copyBytes(rawRepresentation)) }
    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey { do { let key = try Ed25519PrivateKey(seed: signingKey.bytes.span); return VerifyingKey(bytes: [UInt8](try key.publicKey())) } catch { preconditionFailure("swift-ssl Ed25519 public-key derivation failed") } }
    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] { signingKey.bytes }
    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] { verifyingKey.bytes }
    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] { do { let key = try Ed25519PrivateKey(seed: signingKey.bytes.span); return [UInt8](try Ed25519.sign(message: message, using: key)) } catch { throw .providerFailure } }
    public static func isValid(signature: Span<UInt8>, for message: Span<UInt8>, with verifyingKey: VerifyingKey) -> Bool { do { let key = try Ed25519PublicKey(bytes: verifyingKey.bytes.span); return try Ed25519.verify(signature: signature, message: message, using: key) } catch { return false } }
}

private enum SSLECDSA {
    static func der(raw: [UInt8], scalar: Int) throws(CryptoError) -> [UInt8] { do { return try ECDSASignatureDER.encode(rawRepresentation: raw, scalarByteCount: scalar) } catch { throw .providerFailure } }
    static func raw(der: [UInt8], scalar: Int) -> [UInt8]? {
        do {
            return try ECDSASignatureDER.decode(
                derRepresentation: der,
                scalarByteCount: scalar
            )
        } catch {
            return nil
        }
    }
}

public enum SSLBackendP256Signature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct VerifyingKey: Sendable { fileprivate let bytes: [UInt8] }
    public static func generateSigningKey() throws(CryptoError) -> SigningKey { let bytes = SSLBackendRandom().randomBytes(32); do { _ = try P256PrivateKey(bytes: bytes.span); return SigningKey(bytes: bytes) } catch { throw .providerFailure } }
    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey { guard rawRepresentation.count == 32 else { throw .invalidLength(expected: 32, actual: rawRepresentation.count) }; do { _ = try P256PrivateKey(bytes: rawRepresentation) } catch { throw .invalidKeyMaterial }; return SigningKey(bytes: copyBytes(rawRepresentation)) }
    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey { guard rawRepresentation.count == 65 else { throw .invalidLength(expected: 65, actual: rawRepresentation.count) }; do { _ = try P256PublicKey(bytes: rawRepresentation) } catch { throw .invalidKeyMaterial }; return VerifyingKey(bytes: copyBytes(rawRepresentation)) }
    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey { do { let key = try P256PrivateKey(bytes: signingKey.bytes.span); return VerifyingKey(bytes: copyBytes(key.publicKey().span)) } catch { preconditionFailure("swift-ssl P-256 signing public-key derivation failed") } }
    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] { signingKey.bytes }
    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] { verifyingKey.bytes }
    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] { do { let key = try P256PrivateKey(bytes: signingKey.bytes.span); var digest = [UInt8](repeating: 0, count: 32); var destination = digest.mutableSpan; try SHA256.hash(message, into: &destination); return try SSLECDSA.der(raw: [UInt8](try P256ECDSA.sign(messageHash: digest.span, using: key)), scalar: 32) } catch { throw .providerFailure } }
    public static func isValid(signature: Span<UInt8>, for message: Span<UInt8>, with verifyingKey: VerifyingKey) -> Bool { guard let raw = SSLECDSA.raw(der: copyBytes(signature), scalar: 32) else { return false }; do { let key = try P256PublicKey(bytes: verifyingKey.bytes.span); var digest = [UInt8](repeating: 0, count: 32); var destination = digest.mutableSpan; try SHA256.hash(message, into: &destination); return try P256ECDSA.verify(signature: raw.span, messageHash: digest.span, using: key) } catch { return false } }
}

/// Raw IEEE P1363 P-256 signatures (`r || s`) for protocol layers that define
/// their own signature encoding, such as Noise and libp2p identity proofs.
///
/// The key representation is intentionally identical to
/// `SSLBackendP256Signature`.  Only the signature representation differs: the
/// TLS-facing scheme above returns DER, while this scheme returns the fixed
/// width 64-byte value produced by `P256ECDSA`.
public enum SSLBackendRawP256Signature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct VerifyingKey: Sendable { fileprivate let bytes: [UInt8] }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        let bytes = SSLBackendRandom().randomBytes(32)
        do {
            _ = try P256PrivateKey(bytes: bytes.span)
            return SigningKey(bytes: bytes)
        } catch {
            throw .providerFailure
        }
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        guard rawRepresentation.count == 32 else {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
        do {
            _ = try P256PrivateKey(bytes: rawRepresentation)
        } catch {
            throw .invalidKeyMaterial
        }
        return SigningKey(bytes: copyBytes(rawRepresentation))
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        guard rawRepresentation.count == 65 else {
            throw .invalidLength(expected: 65, actual: rawRepresentation.count)
        }
        do {
            _ = try P256PublicKey(bytes: rawRepresentation)
        } catch {
            throw .invalidKeyMaterial
        }
        return VerifyingKey(bytes: copyBytes(rawRepresentation))
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        do {
            let key = try P256PrivateKey(bytes: signingKey.bytes.span)
            return VerifyingKey(bytes: copyBytes(key.publicKey().span))
        } catch {
            preconditionFailure("swift-ssl P-256 signing public-key derivation failed")
        }
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        signingKey.bytes
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        verifyingKey.bytes
    }

    public static func sign(
        _ message: Span<UInt8>,
        with signingKey: SigningKey
    ) throws(CryptoError) -> [UInt8] {
        do {
            let key = try P256PrivateKey(bytes: signingKey.bytes.span)
            var digest = [UInt8](repeating: 0, count: 32)
            var destination = digest.mutableSpan
            try SHA256.hash(message, into: &destination)
            return [UInt8](try P256ECDSA.sign(messageHash: digest.span, using: key))
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard signature.count == 64 else { return false }
        do {
            let key = try P256PublicKey(bytes: verifyingKey.bytes.span)
            var digest = [UInt8](repeating: 0, count: 32)
            var destination = digest.mutableSpan
            try SHA256.hash(message, into: &destination)
            return try P256ECDSA.verify(
                signature: signature,
                messageHash: digest.span,
                using: key
            )
        } catch {
            return false
        }
    }
}

/// P-384 ECDSA backed by `swift-ssl`. The provider exposes the DER form used by
/// TLS CertificateVerify and certificate signatures.
public enum SSLBackendP384Signature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct VerifyingKey: Sendable { fileprivate let bytes: [UInt8] }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        do {
            let key = try P384PrivateKey.generate()
            return key.withBorrowedBytes { SigningKey(bytes: copyBytes($0)) }
        } catch {
            throw .providerFailure
        }
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        guard rawRepresentation.count == P384PrivateKey.byteCount else {
            throw .invalidLength(expected: P384PrivateKey.byteCount, actual: rawRepresentation.count)
        }
        do {
            _ = try P384PrivateKey(bytes: rawRepresentation)
        } catch {
            throw .invalidKeyMaterial
        }
        return SigningKey(bytes: copyBytes(rawRepresentation))
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        guard rawRepresentation.count == P384PublicKey.uncompressedByteCount else {
            throw .invalidLength(
                expected: P384PublicKey.uncompressedByteCount,
                actual: rawRepresentation.count
            )
        }
        do {
            _ = try P384PublicKey(bytes: rawRepresentation)
        } catch {
            throw .invalidKeyMaterial
        }
        return VerifyingKey(bytes: copyBytes(rawRepresentation))
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        do {
            let key = try P384PrivateKey(bytes: signingKey.bytes.span)
            return VerifyingKey(bytes: copyBytes(key.publicKey().span))
        } catch {
            preconditionFailure("swift-ssl P-384 signing public-key derivation failed")
        }
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        signingKey.bytes
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        verifyingKey.bytes
    }

    public static func sign(
        _ message: Span<UInt8>,
        with signingKey: SigningKey
    ) throws(CryptoError) -> [UInt8] {
        do {
            let key = try P384PrivateKey(bytes: signingKey.bytes.span)
            var digest = [UInt8](repeating: 0, count: SHA384.digestByteCount)
            var destination = digest.mutableSpan
            try SHA384.hash(message, into: &destination)
            let raw = try P384ECDSA.sign(messageHash: digest.span, using: key)
            return try SSLECDSA.der(raw: Array(raw), scalar: P384PrivateKey.byteCount)
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard let raw = SSLECDSA.raw(
            der: copyBytes(signature),
            scalar: P384PrivateKey.byteCount
        ) else { return false }
        do {
            let key = try P384PublicKey(bytes: verifyingKey.bytes.span)
            var digest = [UInt8](repeating: 0, count: SHA384.digestByteCount)
            var destination = digest.mutableSpan
            try SHA384.hash(message, into: &destination)
            return try P384ECDSA.verify(
                signature: raw.span,
                messageHash: digest.span,
                using: key
            )
        } catch {
            return false
        }
    }
}

/// Raw IEEE P1363 P-384 signatures (`r || s`) for protocol layers that carry
/// fixed-width ECDSA values instead of DER.
public enum SSLBackendRawP384Signature: P2PCoreCrypto.SignatureScheme {
    public struct SigningKey: Sendable { fileprivate let bytes: [UInt8] }
    public struct VerifyingKey: Sendable { fileprivate let bytes: [UInt8] }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        do {
            let key = try P384PrivateKey.generate()
            return key.withBorrowedBytes { SigningKey(bytes: copyBytes($0)) }
        } catch {
            throw .providerFailure
        }
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        guard rawRepresentation.count == P384PrivateKey.byteCount else {
            throw .invalidLength(expected: P384PrivateKey.byteCount, actual: rawRepresentation.count)
        }
        do { _ = try P384PrivateKey(bytes: rawRepresentation) }
        catch { throw .invalidKeyMaterial }
        return SigningKey(bytes: copyBytes(rawRepresentation))
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        guard rawRepresentation.count == P384PublicKey.uncompressedByteCount else {
            throw .invalidLength(
                expected: P384PublicKey.uncompressedByteCount,
                actual: rawRepresentation.count
            )
        }
        do { _ = try P384PublicKey(bytes: rawRepresentation) }
        catch { throw .invalidKeyMaterial }
        return VerifyingKey(bytes: copyBytes(rawRepresentation))
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        do {
            let key = try P384PrivateKey(bytes: signingKey.bytes.span)
            return VerifyingKey(bytes: copyBytes(key.publicKey().span))
        } catch {
            preconditionFailure("swift-ssl P-384 raw-signing public-key derivation failed")
        }
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] { signingKey.bytes }
    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] { verifyingKey.bytes }

    public static func sign(
        _ message: Span<UInt8>,
        with signingKey: SigningKey
    ) throws(CryptoError) -> [UInt8] {
        do {
            let key = try P384PrivateKey(bytes: signingKey.bytes.span)
            var digest = [UInt8](repeating: 0, count: SHA384.digestByteCount)
            var destination = digest.mutableSpan
            try SHA384.hash(message, into: &destination)
            return Array(try P384ECDSA.sign(messageHash: digest.span, using: key))
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard signature.count == P384PrivateKey.byteCount * 2 else { return false }
        do {
            let key = try P384PublicKey(bytes: verifyingKey.bytes.span)
            var digest = [UInt8](repeating: 0, count: SHA384.digestByteCount)
            var destination = digest.mutableSpan
            try SHA384.hash(message, into: &destination)
            return try P384ECDSA.verify(
                signature: signature,
                messageHash: digest.span,
                using: key
            )
        } catch {
            return false
        }
    }
}

// MARK: Ambient capabilities

public struct SSLBackendRandom: P2PCoreCrypto.RandomSource {
    public init() {}
    public func randomBytes(_ count: Int) -> [UInt8] { var output = [UInt8](repeating: 0, count: max(0, count)); fill(&output); return output }
    public func fill(_ buffer: inout [UInt8]) { do { var destination = buffer.mutableSpan; try SystemEntropySource().fill(&destination) } catch { preconditionFailure("swift-ssl entropy source failed") } }
}

public struct SSLBackendClock: P2PCoreCrypto.MonotonicClock {
    public init() {}
    public func monotonicMillis() -> UInt64 {
        do { return try SystemMonotonicClock().now().ticks / 1_000_000 }
        catch { preconditionFailure("swift-ssl monotonic clock failed") }
    }
    public func monotonicNanos() -> UInt64 {
        do { return try SystemMonotonicClock().now().ticks }
        catch { preconditionFailure("swift-ssl monotonic clock failed") }
    }
}

public enum SSLBackendHeaderProtection: P2PCoreCrypto.HeaderProtectionProvider {
    public static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        do { return Array(try QUICHeaderProtection.aes(key: key, sample: sample)) }
        catch { throw .providerFailure }
    }
    public static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        do { return Array(try QUICHeaderProtection.chaCha20(key: key, sample: sample)) }
        catch { throw .providerFailure }
    }
}

public enum SSLBackendProvider: P2PCoreCrypto.CryptoProvider {
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

    public static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> SSLBackendAESGCM { try SSLBackendAESGCM(key: key) }
    public static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> SSLBackendAESGCM { try SSLBackendAESGCM(key: key) }
    public static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> SSLBackendChaChaPoly { try SSLBackendChaChaPoly(key: key) }
    public static let random = SSLBackendRandom()
    public static let clock = SSLBackendClock()
}
