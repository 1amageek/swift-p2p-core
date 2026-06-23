// LibP2PIdentityTests.swift
// Protobuf decode/round-trip, PeerID multihash framing (identity vs SHA-256),
// signature-message construction, and fail-closed negatives.

import Testing
@testable import P2PCoreDER

@Suite("LibP2PIdentity")
struct LibP2PIdentityTests {

    /// Reference protobuf encoder mirroring PublicKeyProtobuf.encode.
    static func encodeProtobuf(keyType: UInt64, keyData: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        out.append(0x08)                                   // field 1, varint
        out.append(contentsOf: LibP2PIdentity.encodeVarint(keyType))
        out.append(0x12)                                   // field 2, length-delimited
        out.append(contentsOf: LibP2PIdentity.encodeVarint(UInt64(keyData.count)))
        out.append(contentsOf: keyData)
        return out
    }

    @Test func decode_ed25519_roundTrip() throws {
        let key = [UInt8](repeating: 0xAB, count: 32)
        let pb = Self.encodeProtobuf(keyType: 1, keyData: key)
        let (keyType, keyBytes) = try LibP2PIdentity.decodePublicKey(pb)
        #expect(keyType == .ed25519)
        #expect(keyBytes == key)
    }

    @Test func decode_ecdsa_roundTrip() throws {
        let key = [UInt8](repeating: 0x04, count: 65)
        let pb = Self.encodeProtobuf(keyType: 3, keyData: key)
        let (keyType, keyBytes) = try LibP2PIdentity.decodePublicKey(pb)
        #expect(keyType == .ecdsa)
        #expect(keyBytes == key)
    }

    @Test func decode_unknownKeyType_throws() {
        let pb = Self.encodeProtobuf(keyType: 99, keyData: [0x00])
        #expect(throws: LibP2PIdentityError.unknownKeyType(99)) {
            _ = try LibP2PIdentity.decodePublicKey(pb)
        }
    }

    @Test func decode_unknownField_throws() {
        // field 3, wire type 0 — not part of the message.
        var pb = [UInt8]()
        pb.append(0x18)                            // (3<<3)|0
        pb.append(contentsOf: LibP2PIdentity.encodeVarint(7))
        #expect(throws: LibP2PIdentityError.invalidProtobuf) {
            _ = try LibP2PIdentity.decodePublicKey(pb)
        }
    }

    @Test func decode_truncatedLength_throws() {
        // field 2 declares 10 bytes but supplies 1 (0xAA).
        let pb: [UInt8] = [0x08, 0x01, 0x12, 0x0A, 0xAA]
        #expect(throws: LibP2PIdentityError.invalidProtobuf) {
            _ = try LibP2PIdentity.decodePublicKey(pb)
        }
    }

    @Test func decode_keyDataTooLarge_throws() {
        let key = [UInt8](repeating: 0x00, count: 100)
        let pb = Self.encodeProtobuf(keyType: 1, keyData: key)
        #expect(throws: LibP2PIdentityError.keyDataTooLarge(100)) {
            _ = try LibP2PIdentity.decodePublicKey(pb, maxKeyDataLength: 50)
        }
    }

    // MARK: PeerID multihash framing

    @Test func peerID_ed25519_usesIdentityMultihash() throws {
        let key = [UInt8](repeating: 0x77, count: 32)
        let pb = Self.encodeProtobuf(keyType: 1, keyData: key)   // 36 bytes <= 42
        let mh = try LibP2PIdentity.peerIDMultihash(protobufPubKey: pb, sha256: { _ in
            Issue.record("SHA-256 must not be called for identity-encoded keys")
            return [UInt8](repeating: 0, count: 32)
        })
        // 00 <varint len=36> <protobuf>
        #expect(mh[0] == 0x00)
        #expect(mh[1] == 0x24)            // 36
        #expect(Array(mh.dropFirst(2)) == pb)
    }

    @Test func peerID_ecdsa_usesSHA256Multihash() throws {
        let key = [UInt8](repeating: 0x04, count: 65)
        let pb = Self.encodeProtobuf(keyType: 3, keyData: key)   // > 42 bytes
        let fakeDigest = [UInt8](0..<32).map { UInt8($0) }
        let mh = try LibP2PIdentity.peerIDMultihash(protobufPubKey: pb, sha256: { input in
            #expect(input == pb)
            return fakeDigest
        })
        // 12 20 <digest>
        #expect(mh[0] == 0x12)
        #expect(mh[1] == 0x20)
        #expect(Array(mh.dropFirst(2)) == fakeDigest)
        #expect(mh.count == 34)
    }

    @Test func peerID_ed25519_largeKey_fallsBackToSHA256() throws {
        // An Ed25519-typed protobuf > 42 bytes (oversized key) must use SHA-256,
        // not identity. (No silent identity-encode of an oversized blob.)
        let key = [UInt8](repeating: 0x77, count: 64)
        let pb = Self.encodeProtobuf(keyType: 1, keyData: key)   // > 42 bytes
        let fakeDigest = [UInt8](repeating: 0x9, count: 32)
        let mh = try LibP2PIdentity.peerIDMultihash(protobufPubKey: pb, sha256: { _ in fakeDigest })
        #expect(mh[0] == 0x12)
        #expect(mh[1] == 0x20)
    }

    // MARK: SignedKey verification dispatch

    @Test func verifySignedKey_ed25519_dispatch() throws {
        let key = [UInt8](repeating: 0xAB, count: 32)
        let pb = Self.encodeProtobuf(keyType: 1, keyData: key)
        let spki = [UInt8](repeating: 0x30, count: 10)
        let sig = [UInt8](repeating: 0x55, count: 64)
        var sawEd = false
        let ok = try LibP2PIdentity.verifySignedKey(
            protobufPubKey: pb, signature: sig, spkiDER: spki,
            verifyEd25519: { pk, s, msg in
                sawEd = true
                #expect(pk == key)
                #expect(s == sig)
                #expect(msg == LibP2PIdentity.signatureMessage(spkiDER: spki))
                return true
            },
            verifyP256DER: { _, _, _ in Issue.record("wrong dispatch"); return false }
        )
        #expect(ok)
        #expect(sawEd)
    }

    @Test func verifySignedKey_unsupportedKeyType_throws() {
        let key = [UInt8](repeating: 0x02, count: 33)
        let pb = Self.encodeProtobuf(keyType: 2, keyData: key)   // secp256k1
        #expect(throws: LibP2PIdentityError.unsupportedKeyType(.secp256k1)) {
            _ = try LibP2PIdentity.verifySignedKey(
                protobufPubKey: pb, signature: [], spkiDER: [],
                verifyEd25519: { _, _, _ in true },
                verifyP256DER: { _, _, _ in true }
            )
        }
    }

    @Test func signatureMessage_prefix() {
        let msg = LibP2PIdentity.signatureMessage(spkiDER: [0xAA])
        let prefix = Array(msg.prefix(21))
        #expect(prefix == Array("libp2p-tls-handshake:".utf8))
        #expect(msg.last == 0xAA)
    }
}
