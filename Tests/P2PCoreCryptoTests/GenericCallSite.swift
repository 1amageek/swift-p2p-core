// GenericCallSite.swift
// The worked QUIC packet-protector seam over `<C: CryptoProvider>` (§3.4). It
// lives in a *Core* target in production; here it validates the seam compiles
// and runs with NO `any` anywhere (A9).

import Testing
@testable import P2PCoreCrypto

struct PacketProtector<C: CryptoProvider, A: AEAD>: Sendable {
    let aead: A          // built once per key epoch from C.makeAESGCM128 / *256 / *ChaChaPoly
    let iv: [UInt8]      // 12-byte write IV derived via C.HKDFSHA256/384

    func nonce(packetNumber: UInt64) -> [UInt8] {
        var n = iv                                   // RFC 9001 §5.1: nonce = IV XOR PN (right-aligned)
        var pn = packetNumber
        var i = n.count - 1
        while pn != 0 && i >= 0 { n[i] ^= UInt8(truncatingIfNeeded: pn); pn >>= 8; i -= 1 }
        return n
    }

    func seal(plaintext: Span<UInt8>, packetNumber: UInt64, header: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        let n = nonce(packetNumber: packetNumber)
        return try aead.seal(plaintext, nonce: n.span, aad: header)
    }
    func open(ciphertext: Span<UInt8>, packetNumber: UInt64, header: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        let n = nonce(packetNumber: packetNumber)
        return try aead.open(ciphertext, nonce: n.span, aad: header)
    }
}

// Per-suite runtime selection: a CLOSED enum over the mandatory AEADs replaces a
// heterogeneous `any` collection (the Embedded-clean substitution for `any`, N1).
enum SuiteProtector<C: CryptoProvider>: Sendable {
    case aes128(PacketProtector<C, C.AESGCM128>)
    case aes256(PacketProtector<C, C.AESGCM256>)
    case chaCha(PacketProtector<C, C.ChaChaPoly>)

    func seal(_ pt: Span<UInt8>, pn: UInt64, header: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        switch self {
        case .aes128(let p): return try p.seal(plaintext: pt, packetNumber: pn, header: header)
        case .aes256(let p): return try p.seal(plaintext: pt, packetNumber: pn, header: header)
        case .chaCha(let p): return try p.seal(plaintext: pt, packetNumber: pn, header: header)
        }
    }

    func open(_ ct: Span<UInt8>, pn: UInt64, header: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        switch self {
        case .aes128(let p): return try p.open(ciphertext: ct, packetNumber: pn, header: header)
        case .aes256(let p): return try p.open(ciphertext: ct, packetNumber: pn, header: header)
        case .chaCha(let p): return try p.open(ciphertext: ct, packetNumber: pn, header: header)
        }
    }
}

// Worked derivation: HKDF-expand the write IV, then build a protector — uses ONLY
// associatedtypes of C (no `any`). Compiled in both modes (A9).
func deriveProtector<C: CryptoProvider>(
    _ provider: C.Type, aead: C.AESGCM128, secret: Span<UInt8>
) throws(CryptoError) -> PacketProtector<C, C.AESGCM128> {
    let hkdf = C.HKDFSHA256()
    let label: [UInt8] = [0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76] // "quic iv"
    let iv = try hkdf.expand(prk: secret, info: label.span, length: 12)
    return PacketProtector<C, C.AESGCM128>(aead: aead, iv: iv)
}

/// Exercises a provider end-to-end through its associatedtypes only (no `any`):
/// derive a key, build an AEAD, seal then open a payload. Returns the recovered
/// plaintext length.
func exerciseProvider<C: CryptoProvider>(_ provider: C.Type) throws(CryptoError) -> Int {
    let key = [UInt8](repeating: 0x2B, count: 16)
    let aead = try C.makeAESGCM128(key: key.span)
    let secret = [UInt8](repeating: 0x0C, count: 32)
    let protector = try deriveProtector(C.self, aead: aead, secret: secret.span)
    let plaintext: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
    let header: [UInt8] = [0xC0, 0x00, 0x00, 0x00, 0x01]
    let sealed = try protector.seal(plaintext: plaintext.span, packetNumber: 7, header: header.span)
    let recovered = try protector.open(ciphertext: sealed.span, packetNumber: 7, header: header.span)
    return recovered.count
}
