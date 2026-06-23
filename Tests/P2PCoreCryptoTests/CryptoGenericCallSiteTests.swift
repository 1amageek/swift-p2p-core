// CryptoGenericCallSiteTests.swift
// Guards against `any` creeping back in: the QUIC-style protector seam runs
// purely through generics + a closed enum (A9).

import Testing
@testable import P2PCoreCrypto

@Suite("Crypto generic call site")
struct CryptoGenericCallSiteTests {
    @Test func generic_aeadRoundTrip_overSomeAEAD_compilesAndRuns() throws {
        func roundTrip<A: AEAD>(_ aead: A, plaintext: [UInt8]) throws(CryptoError) -> [UInt8] {
            let nonce = [UInt8](repeating: 0, count: A.nonceLength)
            let aad: [UInt8] = []
            let sealed = try aead.seal(plaintext.span, nonce: nonce.span, aad: aad.span)
            return try aead.open(sealed.span, nonce: nonce.span, aad: aad.span)
        }
        let aead = StubAEAD(key: [UInt8](repeating: 0x33, count: 16))
        let pt: [UInt8] = [5, 6, 7, 8, 9]
        #expect(try roundTrip(aead, plaintext: pt) == pt)
    }

    @Test func generic_deriveProtector_overCryptoProvider_buildsProtector() throws {
        let aead = try StubProvider.makeAESGCM128(key: [UInt8](repeating: 0, count: 16).span)
        let secret = [UInt8](repeating: 0x0C, count: 32)
        let protector = try deriveProtector(StubProvider.self, aead: aead, secret: secret.span)
        #expect(protector.iv.count == 12)
    }

    @Test func generic_suiteProtector_enumDispatch_sealsForAllThreeSuites() throws {
        let secret = [UInt8](repeating: 0x0C, count: 32)
        let aead128 = try StubProvider.makeAESGCM128(key: [UInt8](repeating: 0, count: 16).span)
        let aead256 = try StubProvider.makeAESGCM256(key: [UInt8](repeating: 0, count: 32).span)
        let chacha = try StubProvider.makeChaChaPoly(key: [UInt8](repeating: 0, count: 32).span)

        let p128 = try deriveProtector(StubProvider.self, aead: aead128, secret: secret.span)
        let p256 = PacketProtector<StubProvider, StubProvider.AESGCM256>(aead: aead256, iv: [UInt8](repeating: 0, count: 12))
        let pcha = PacketProtector<StubProvider, StubProvider.ChaChaPoly>(aead: chacha, iv: [UInt8](repeating: 0, count: 12))

        let suites: [SuiteProtector<StubProvider>] = [.aes128(p128), .aes256(p256), .chaCha(pcha)]
        let plaintext: [UInt8] = [1, 2, 3]
        let header: [UInt8] = [0xC0]
        for suite in suites {
            let sealed = try suite.seal(plaintext.span, pn: 1, header: header.span)
            #expect(sealed.count == plaintext.count + StubAEAD.tagLength)
            let opened = try suite.open(sealed.span, pn: 1, header: header.span)
            #expect(opened == plaintext)
        }
    }

    @Test func generic_exerciseProvider_endToEnd_returnsExpectedLength() throws {
        #expect(try exerciseProvider(StubProvider.self) == 4)
    }
}
