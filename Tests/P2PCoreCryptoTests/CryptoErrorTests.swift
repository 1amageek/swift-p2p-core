// CryptoErrorTests.swift
// The typed-error contracts: short/bad AEAD input, wrong key length, HKDF over
// max, constant-time MAC rejection. No silent fallback.

import Testing
@testable import P2PCoreCrypto

@Suite("Crypto errors")
struct CryptoErrorTests {
    @Test func aead_open_shortInput_throwsInvalidLength() {
        let aead = StubAEAD(key: [UInt8](repeating: 0, count: 16))
        let nonce = [UInt8](repeating: 0, count: StubAEAD.nonceLength)
        let aad: [UInt8] = []
        let tooShort = [UInt8](repeating: 0, count: StubAEAD.tagLength - 1)
        #expect(throws: CryptoError.invalidLength(expected: StubAEAD.tagLength, actual: StubAEAD.tagLength - 1)) {
            _ = try aead.open(tooShort.span, nonce: nonce.span, aad: aad.span)
        }
    }

    @Test func aead_open_badTag_throwsAuthenticationFailure() throws {
        let aead = StubAEAD(key: [UInt8](repeating: 0x42, count: 16))
        let nonce = [UInt8](repeating: 0, count: StubAEAD.nonceLength)
        let aad: [UInt8] = [1, 2]
        let pt: [UInt8] = [9, 8, 7]
        var sealed = try aead.seal(pt.span, nonce: nonce.span, aad: aad.span)
        // Tamper with the tag (last byte).
        sealed[sealed.count - 1] ^= 0xFF
        #expect(throws: CryptoError.authenticationFailure) {
            _ = try aead.open(sealed.span, nonce: nonce.span, aad: aad.span)
        }
    }

    @Test func provider_makeAESGCM128_wrongKeyLength_throwsInvalidLength() {
        let wrongKey = [UInt8](repeating: 0, count: 8)
        #expect(throws: CryptoError.invalidLength(expected: 16, actual: 8)) {
            _ = try StubProvider.makeAESGCM128(key: wrongKey.span)
        }
    }

    @Test func hkdf_expand_overMaxLength_throwsInvalidLength() {
        let kdf = StubHKDFSHA256()
        let prk = [UInt8](repeating: 0, count: 32)
        let info: [UInt8] = []
        let overMax = 255 * StubHKDFSHA256.Hash.digestLength + 1
        #expect(throws: CryptoError.invalidLength(expected: 255 * StubHKDFSHA256.Hash.digestLength, actual: overMax)) {
            _ = try kdf.expand(prk: prk.span, info: info.span, length: overMax)
        }
    }

    @Test func mac_isValid_constantTimeCompare_rejectsTamperedMac() {
        let key = [UInt8](repeating: 0x7, count: 8)
        let message: [UInt8] = [10, 20, 30]
        var mac = StubHMAC.authenticationCode(for: message.span, key: key.span)
        let validBefore = StubHMAC.isValid(mac.span, for: message.span, key: key.span)
        #expect(validBefore)
        mac[0] ^= 0xFF
        let validAfter = StubHMAC.isValid(mac.span, for: message.span, key: key.span)
        #expect(validAfter == false)
    }
}
