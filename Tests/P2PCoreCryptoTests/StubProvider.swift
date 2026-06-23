// StubProvider.swift
// A concrete, test-only provider proving the entire crypto protocol family is
// satisfiable with `associatedtype`s + generics and NO `any` (the "shape test",
// A8). This is NOT cryptography: the primitives use trivial, deterministic
// transforms purely to exercise the contracts (round-trips, lengths, errors).

import Testing
@testable import P2PCoreCrypto

// MARK: - Helpers

/// Copies a borrowed span into an owned array (the stubs work on arrays).
func toArray(_ span: Span<UInt8>) -> [UInt8] {
    var out = [UInt8]()
    out.reserveCapacity(span.count)
    for i in 0..<span.count { out.append(span[i]) }
    return out
}

// MARK: - AEAD stubs

/// Generic AEAD stub: a keystream XOR cipher with a deterministic 16-byte tag.
/// Parameterised by nonce length so distinct concrete types exist per suite.
struct StubAEAD: AEAD {
    static var nonceLength: Int { 12 }
    static var tagLength: Int { 16 }

    let key: [UInt8]

    private func keystreamByte(_ index: Int, nonce: [UInt8]) -> UInt8 {
        let k = key.isEmpty ? 0 : key[index % key.count]
        let n = nonce.isEmpty ? 0 : nonce[index % nonce.count]
        return k ^ n ^ UInt8(truncatingIfNeeded: index)
    }

    private func tag(_ data: [UInt8], aad: [UInt8]) -> [UInt8] {
        var acc = [UInt8](repeating: 0, count: Self.tagLength)
        for (i, byte) in data.enumerated() { acc[i % Self.tagLength] ^= byte }
        for (i, byte) in aad.enumerated() { acc[i % Self.tagLength] ^= byte &+ 0x5A }
        for (i, byte) in key.enumerated() { acc[i % Self.tagLength] ^= byte &+ 0xA5 }
        return acc
    }

    func seal(_ plaintext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        let pt = toArray(plaintext)
        let n = toArray(nonce)
        let ad = toArray(aad)
        var ct = [UInt8]()
        ct.reserveCapacity(pt.count + Self.tagLength)
        for (i, byte) in pt.enumerated() { ct.append(byte ^ keystreamByte(i, nonce: n)) }
        ct.append(contentsOf: tag(ct, aad: ad))
        return ct
    }

    func open(_ ciphertext: Span<UInt8>, nonce: Span<UInt8>, aad: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        let ct = toArray(ciphertext)
        guard ct.count >= Self.tagLength else {
            throw CryptoError.invalidLength(expected: Self.tagLength, actual: ct.count)
        }
        let n = toArray(nonce)
        let ad = toArray(aad)
        let body = Array(ct[0..<(ct.count - Self.tagLength)])
        let receivedTag = Array(ct[(ct.count - Self.tagLength)...])
        let expectedTag = tag(body, aad: ad)
        guard receivedTag == expectedTag else {
            throw CryptoError.authenticationFailure
        }
        var pt = [UInt8]()
        pt.reserveCapacity(body.count)
        for (i, byte) in body.enumerated() { pt.append(byte ^ keystreamByte(i, nonce: n)) }
        return pt
    }
}

// MARK: - Hash stubs (distinct digest lengths to satisfy SHA256 != SHA384)

/// Deterministic non-cryptographic 32-byte "hash".
struct StubSHA256: HashFunction {
    static var digestLength: Int { 32 }
    static var blockLength: Int { 64 }
    private var acc: [UInt8]
    init() { acc = [UInt8](repeating: 0, count: Self.digestLength) }
    mutating func update(_ data: Span<UInt8>) {
        for i in 0..<data.count { acc[i % Self.digestLength] = acc[i % Self.digestLength] &+ data[i] }
    }
    consuming func finalize() -> [UInt8] { acc }
}

/// Deterministic non-cryptographic 48-byte "hash".
struct StubSHA384: HashFunction {
    static var digestLength: Int { 48 }
    static var blockLength: Int { 128 }
    private var acc: [UInt8]
    init() { acc = [UInt8](repeating: 0, count: Self.digestLength) }
    mutating func update(_ data: Span<UInt8>) {
        for i in 0..<data.count { acc[i % Self.digestLength] = acc[i % Self.digestLength] &+ data[i] }
    }
    consuming func finalize() -> [UInt8] { acc }
}

// MARK: - HKDF stubs (hash-bound)

struct StubHKDFSHA256: KeyDerivation {
    typealias Hash = StubSHA256
    init() {}
    func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        StubSHA256.hash(ikm)
    }
    func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(CryptoError) -> [UInt8] {
        let maxLength = 255 * Hash.digestLength
        guard length <= maxLength else {
            throw CryptoError.invalidLength(expected: maxLength, actual: length)
        }
        let prkArray = toArray(prk)
        var out = [UInt8]()
        out.reserveCapacity(length)
        for i in 0..<length {
            let base = prkArray.isEmpty ? UInt8(0) : prkArray[i % prkArray.count]
            out.append(base &+ UInt8(truncatingIfNeeded: i))
        }
        return out
    }
}

struct StubHKDFSHA384: KeyDerivation {
    typealias Hash = StubSHA384
    init() {}
    func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        StubSHA384.hash(ikm)
    }
    func expand(prk: Span<UInt8>, info: Span<UInt8>, length: Int) throws(CryptoError) -> [UInt8] {
        let maxLength = 255 * Hash.digestLength
        guard length <= maxLength else {
            throw CryptoError.invalidLength(expected: maxLength, actual: length)
        }
        let prkArray = toArray(prk)
        var out = [UInt8]()
        out.reserveCapacity(length)
        for i in 0..<length {
            let base = prkArray.isEmpty ? UInt8(0) : prkArray[i % prkArray.count]
            out.append(base &+ UInt8(truncatingIfNeeded: i))
        }
        return out
    }
}

// MARK: - MAC stub

struct StubHMAC: MessageAuthenticationCode {
    static var macLength: Int { 32 }
    private var key: [UInt8]
    private var acc: [UInt8]
    init(key: Span<UInt8>) {
        self.key = toArray(key)
        self.acc = [UInt8](repeating: 0, count: Self.macLength)
        for (i, byte) in self.key.enumerated() { acc[i % Self.macLength] ^= byte }
    }
    mutating func update(_ data: Span<UInt8>) {
        for i in 0..<data.count { acc[i % Self.macLength] = acc[i % Self.macLength] &+ data[i] }
    }
    consuming func finalize() -> [UInt8] { acc }
    static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        var mac = StubHMAC(key: key)
        mac.update(message)
        return mac.finalize()
    }
    static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        let expected = authenticationCode(for: message, key: key)
        let provided = toArray(mac)
        guard expected.count == provided.count else { return false }
        // Constant-time compare: accumulate differences, no early return.
        var diff: UInt8 = 0
        for i in 0..<expected.count { diff |= expected[i] ^ provided[i] }
        return diff == 0
    }
}

// Distinct MAC types so HMACSHA1/256/384 are nominally different.
struct StubHMACSHA1: MessageAuthenticationCode {
    static var macLength: Int { 20 }
    private var acc: [UInt8]
    init(key: Span<UInt8>) {
        acc = [UInt8](repeating: 0, count: Self.macLength)
        for i in 0..<key.count { acc[i % Self.macLength] ^= key[i] }
    }
    mutating func update(_ data: Span<UInt8>) {
        for i in 0..<data.count { acc[i % Self.macLength] = acc[i % Self.macLength] &+ data[i] }
    }
    consuming func finalize() -> [UInt8] { acc }
    static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        var mac = StubHMACSHA1(key: key); mac.update(message); return mac.finalize()
    }
    static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        let expected = authenticationCode(for: message, key: key)
        let provided = toArray(mac)
        guard expected.count == provided.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<expected.count { diff |= expected[i] ^ provided[i] }
        return diff == 0
    }
}

struct StubHMACSHA384: MessageAuthenticationCode {
    static var macLength: Int { 48 }
    private var acc: [UInt8]
    init(key: Span<UInt8>) {
        acc = [UInt8](repeating: 0, count: Self.macLength)
        for i in 0..<key.count { acc[i % Self.macLength] ^= key[i] }
    }
    mutating func update(_ data: Span<UInt8>) {
        for i in 0..<data.count { acc[i % Self.macLength] = acc[i % Self.macLength] &+ data[i] }
    }
    consuming func finalize() -> [UInt8] { acc }
    static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        var mac = StubHMACSHA384(key: key); mac.update(message); return mac.finalize()
    }
    static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        let expected = authenticationCode(for: message, key: key)
        let provided = toArray(mac)
        guard expected.count == provided.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<expected.count { diff |= expected[i] ^ provided[i] }
        return diff == 0
    }
}

// MARK: - Key agreement stub (one type, reused for X25519/P256/P384)

struct StubKeyAgreement: KeyAgreement {
    struct PrivateKey: Sendable { var bytes: [UInt8] }
    struct PublicKey: Sendable { var bytes: [UInt8] }
    static func generatePrivateKey() throws(CryptoError) -> PrivateKey {
        PrivateKey(bytes: [UInt8](repeating: 0x11, count: 32))
    }
    static func privateKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PrivateKey {
        PrivateKey(bytes: toArray(rawRepresentation))
    }
    static func publicKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PublicKey {
        PublicKey(bytes: toArray(rawRepresentation))
    }
    static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        PublicKey(bytes: privateKey.bytes.map { $0 ^ 0xFF })
    }
    static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] { privateKey.bytes }
    static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] { publicKey.bytes }
    static func sharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey) throws(CryptoError) -> [UInt8] {
        guard !peerPublicKey.bytes.isEmpty else { throw CryptoError.keyAgreementFailure }
        var out = [UInt8]()
        let count = max(privateKey.bytes.count, peerPublicKey.bytes.count)
        for i in 0..<count {
            let a = i < privateKey.bytes.count ? privateKey.bytes[i] : 0
            let b = i < peerPublicKey.bytes.count ? peerPublicKey.bytes[i] : 0
            out.append(a ^ b)
        }
        return out
    }
}

// MARK: - Signature stub (one type, reused for Ed25519/P256/P384)

struct StubSignature: SignatureScheme {
    struct SigningKey: Sendable { var bytes: [UInt8] }
    struct VerifyingKey: Sendable { var bytes: [UInt8] }
    static func generateSigningKey() throws(CryptoError) -> SigningKey {
        SigningKey(bytes: [UInt8](repeating: 0x22, count: 32))
    }
    static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        SigningKey(bytes: toArray(rawRepresentation))
    }
    static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        VerifyingKey(bytes: toArray(rawRepresentation))
    }
    static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(bytes: signingKey.bytes.map { $0 ^ 0x0F })
    }
    static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] { signingKey.bytes }
    static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] { verifyingKey.bytes }
    static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] {
        var sig = signingKey.bytes
        for i in 0..<message.count { sig.append(message[i]) }
        return sig
    }
    static func isValid(signature: Span<UInt8>, for message: Span<UInt8>, with verifyingKey: VerifyingKey) -> Bool {
        let sig = toArray(signature)
        let expectedSigning = verifyingKey.bytes.map { $0 ^ 0x0F }
        guard sig.count == expectedSigning.count + message.count else { return false }
        for i in 0..<expectedSigning.count where sig[i] != expectedSigning[i] { return false }
        for i in 0..<message.count where sig[expectedSigning.count + i] != message[i] { return false }
        return true
    }
}

// MARK: - Ambient capability stubs

struct StubRandom: RandomSource {
    func randomBytes(_ count: Int) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(count)
        for i in 0..<count { out.append(UInt8(truncatingIfNeeded: i &* 31 &+ 7)) }
        return out
    }
    func fill(_ buffer: inout [UInt8]) {
        for i in 0..<buffer.count { buffer[i] = UInt8(truncatingIfNeeded: i &* 31 &+ 7) }
    }
}

struct StubClock: MonotonicClock {
    func monotonicMillis() -> UInt64 { 1_000 }
    func monotonicNanos() -> UInt64 { 1_000_000 }
}

struct StubHeaderProtection: HeaderProtectionProvider {
    static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        let s = toArray(sample)
        var mask = [UInt8]()
        for i in 0..<5 { mask.append(i < s.count ? s[i] : 0) }
        return mask
    }
    static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        let s = toArray(sample)
        var mask = [UInt8]()
        for i in 0..<5 { mask.append((i < s.count ? s[i] : 0) ^ 0xCC) }
        return mask
    }
}

// MARK: - The aggregate provider satisfying all 20 associatedtypes

struct StubProvider: CryptoProvider {
    typealias AESGCM128 = StubAEAD
    typealias AESGCM256 = StubAEAD
    typealias ChaChaPoly = StubAEAD

    typealias SHA256 = StubSHA256
    typealias SHA384 = StubSHA384

    typealias HKDFSHA256 = StubHKDFSHA256
    typealias HKDFSHA384 = StubHKDFSHA384

    typealias HMACSHA1 = StubHMACSHA1
    typealias HMACSHA256 = StubHMAC
    typealias HMACSHA384 = StubHMACSHA384

    typealias X25519 = StubKeyAgreement
    typealias P256Agreement = StubKeyAgreement
    typealias P384Agreement = StubKeyAgreement

    typealias Ed25519 = StubSignature
    typealias P256Signature = StubSignature
    typealias P384Signature = StubSignature

    typealias Random = StubRandom
    typealias Clock = StubClock
    typealias HeaderProtection = StubHeaderProtection

    static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> StubAEAD {
        guard key.count == 16 else {
            throw CryptoError.invalidLength(expected: 16, actual: key.count)
        }
        return StubAEAD(key: toArray(key))
    }
    static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> StubAEAD {
        guard key.count == 32 else {
            throw CryptoError.invalidLength(expected: 32, actual: key.count)
        }
        return StubAEAD(key: toArray(key))
    }
    static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> StubAEAD {
        guard key.count == 32 else {
            throw CryptoError.invalidLength(expected: 32, actual: key.count)
        }
        return StubAEAD(key: toArray(key))
    }

    static var random: StubRandom { StubRandom() }
    static var clock: StubClock { StubClock() }
}
