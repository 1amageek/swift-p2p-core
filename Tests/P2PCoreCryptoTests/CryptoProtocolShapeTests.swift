// CryptoProtocolShapeTests.swift
// Shape tests: each primitive protocol and the 20-associatedtype CryptoProvider
// are satisfiable by a concrete stub (A8). No real cryptography here.

import Testing
@testable import P2PCoreCrypto

@Suite("Crypto protocol shape")
struct CryptoProtocolShapeTests {
    @Test func stub_conformsToAEAD() throws {
        let aead = StubAEAD(key: [UInt8](repeating: 0x10, count: 16))
        let pt: [UInt8] = [1, 2, 3, 4]
        let nonce = [UInt8](repeating: 0, count: StubAEAD.nonceLength)
        let aad: [UInt8] = [9, 9]
        let sealed = try aead.seal(pt.span, nonce: nonce.span, aad: aad.span)
        #expect(sealed.count == pt.count + StubAEAD.tagLength)
        let opened = try aead.open(sealed.span, nonce: nonce.span, aad: aad.span)
        #expect(opened == pt)
    }

    @Test func stub_conformsToHashFunction_andDefaultHashWorks() {
        let data: [UInt8] = [1, 2, 3]
        let oneShot = StubSHA256.hash(data.span)
        var incremental = StubSHA256()
        incremental.update(data.span)
        let manual = incremental.finalize()
        #expect(oneShot == manual)
        #expect(oneShot.count == StubSHA256.digestLength)
    }

    @Test func stub_conformsToKeyDerivation_withAssociatedHash() throws {
        let kdf = StubHKDFSHA256()
        let ikm = [UInt8](repeating: 0x5, count: 8)
        let salt: [UInt8] = []
        let info: [UInt8] = []
        let prk = kdf.extract(salt: salt.span, ikm: ikm.span)
        #expect(prk.count == StubHKDFSHA256.Hash.digestLength)
        let okm = try kdf.expand(prk: prk.span, info: info.span, length: 16)
        #expect(okm.count == 16)
    }

    @Test func stub_conformsToMessageAuthenticationCode() {
        let key = [UInt8](repeating: 0x7, count: 8)
        let message: [UInt8] = [10, 20, 30]
        let mac = StubHMAC.authenticationCode(for: message.span, key: key.span)
        #expect(mac.count == StubHMAC.macLength)
        let valid = StubHMAC.isValid(mac.span, for: message.span, key: key.span)
        #expect(valid)
    }

    @Test func stub_conformsToKeyAgreement() throws {
        let priv = try StubKeyAgreement.generatePrivateKey()
        let pub = StubKeyAgreement.publicKey(for: priv)
        let secret = try StubKeyAgreement.sharedSecret(privateKey: priv, peerPublicKey: pub)
        #expect(!secret.isEmpty)
        let raw = StubKeyAgreement.rawRepresentation(of: priv)
        let restored = try StubKeyAgreement.privateKey(rawRepresentation: raw.span)
        #expect(StubKeyAgreement.rawRepresentation(of: restored) == raw)
    }

    @Test func stub_conformsToSignatureScheme() throws {
        let signing = try StubSignature.generateSigningKey()
        let verifying = StubSignature.verifyingKey(for: signing)
        let message: [UInt8] = [42, 43, 44]
        let sig = try StubSignature.sign(message.span, with: signing)
        let valid = StubSignature.isValid(signature: sig.span, for: message.span, with: verifying)
        #expect(valid)
    }

    @Test func stub_conformsToRandomSource() {
        let rng = StubRandom()
        let bytes = rng.randomBytes(8)
        #expect(bytes.count == 8)
        var buffer = [UInt8](repeating: 0, count: 4)
        rng.fill(&buffer)
        #expect(buffer.count == 4)
    }

    @Test func stub_conformsToMonotonicClock() {
        let clock = StubClock()
        #expect(clock.monotonicMillis() == 1_000)
        #expect(clock.monotonicNanos() == 1_000_000)
    }

    @Test func stub_conformsToHeaderProtectionProvider() throws {
        let key = [UInt8](repeating: 0, count: 16)
        let sample = [UInt8](repeating: 0xAB, count: 16)
        let aesMask = try StubHeaderProtection.aesECBBlockMask(key: key.span, sample: sample.span)
        #expect(aesMask.count == 5)
        let chaMask = try StubHeaderProtection.chaCha20BlockMask(key: key.span, sample: sample.span)
        #expect(chaMask.count == 5)
    }

    @Test func stubProvider_conformsToCryptoProvider_allTwentyAssociatedTypes() throws {
        // Touch every associatedtype + member to prove the 20-assoc aggregate
        // (incl. the `where Hash == ...` constraints) is satisfiable.
        let aead128 = try StubProvider.makeAESGCM128(key: [UInt8](repeating: 0, count: 16).span)
        let aead256 = try StubProvider.makeAESGCM256(key: [UInt8](repeating: 0, count: 32).span)
        let chacha = try StubProvider.makeChaChaPoly(key: [UInt8](repeating: 0, count: 32).span)
        _ = aead128; _ = aead256; _ = chacha

        #expect(StubProvider.SHA256.digestLength == 32)
        #expect(StubProvider.SHA384.digestLength == 48)
        #expect(StubProvider.HKDFSHA256.Hash.digestLength == 32)
        #expect(StubProvider.HKDFSHA384.Hash.digestLength == 48)
        #expect(StubProvider.HMACSHA1.macLength == 20)
        #expect(StubProvider.HMACSHA256.macLength == 32)
        #expect(StubProvider.HMACSHA384.macLength == 48)

        _ = try StubProvider.X25519.generatePrivateKey()
        _ = try StubProvider.P256Agreement.generatePrivateKey()
        _ = try StubProvider.P384Agreement.generatePrivateKey()
        _ = try StubProvider.Ed25519.generateSigningKey()
        _ = try StubProvider.P256Signature.generateSigningKey()
        _ = try StubProvider.P384Signature.generateSigningKey()

        #expect(StubProvider.random.randomBytes(1).count == 1)
        #expect(StubProvider.clock.monotonicMillis() == 1_000)
        let sample = [UInt8](repeating: 1, count: 16)
        let hpKey: [UInt8] = []
        let maskLength = try StubProvider.HeaderProtection.aesECBBlockMask(key: hpKey.span, sample: sample.span).count
        #expect(maskLength == 5)
    }
}
