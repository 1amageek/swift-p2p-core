// LibP2PIdentity.swift
// libp2p identity binding: a minimal two-field protobuf decode for the libp2p
// PublicKey message, SignedKey signature verification, and PeerID multihash
// derivation. Crypto is injected as closures (Embedded-clean: no Foundation,
// no `import Crypto`, no `any`). No silent fallback — unknown key/wire types
// throw a typed error.

/// Errors raised by the libp2p identity binding.
public enum LibP2PIdentityError: Error, Equatable, Sendable {
    /// The protobuf was malformed, truncated, or carried an unknown field/wire type.
    case invalidProtobuf
    /// The protobuf key data exceeded the DoS bound.
    case keyDataTooLarge(UInt64)
    /// The KeyType value is not a known libp2p key type.
    case unknownKeyType(UInt64)
    /// The key type is recognized but not supported for verification (RSA / secp256k1).
    case unsupportedKeyType(LibP2PIdentity.KeyType)
}

/// libp2p identity-key helpers over `[UInt8]`.
public enum LibP2PIdentity {

    /// libp2p key types (`message PublicKey { KeyType Type = 1; bytes Data = 2; }`).
    public enum KeyType: UInt64, Sendable, Equatable {
        case rsa = 0
        case ed25519 = 1
        case secp256k1 = 2
        case ecdsa = 3

        /// Identity multihash encoding is used only for small keys (Ed25519).
        var supportsIdentityEncoding: Bool {
            self == .ed25519
        }
    }

    /// The maximum protobuf-encoded length eligible for identity multihash encoding.
    public static let identityEncodingMaxLength = 42

    // MARK: Protobuf decode (two fields, single-occurrence)

    /// Decodes the libp2p PublicKey protobuf: field 1 (varint KeyType), field 2
    /// (length-delimited key bytes). Rejects unknown fields / wire types and
    /// truncation. No silent fallback.
    public static func decodePublicKey(
        _ protobuf: [UInt8],
        maxKeyDataLength: Int = 4096
    ) throws(LibP2PIdentityError) -> (keyType: KeyType, keyBytes: [UInt8]) {
        var offset = 0
        var rawKeyType: UInt64? = nil
        var keyData: [UInt8]? = nil

        while offset < protobuf.count {
            let (fieldTag, tagBytes) = try decodeVarint(protobuf, at: offset)
            offset += tagBytes
            let fieldNumber = fieldTag >> 3
            let wireType = fieldTag & 0x07

            switch (fieldNumber, wireType) {
            case (1, 0):
                let (value, n) = try decodeVarint(protobuf, at: offset)
                offset += n
                rawKeyType = value
            case (2, 2):
                let (length, n) = try decodeVarint(protobuf, at: offset)
                offset += n
                guard length <= UInt64(maxKeyDataLength) else {
                    throw LibP2PIdentityError.keyDataTooLarge(length)
                }
                let keyLength = Int(length)
                let end = offset + keyLength
                guard end <= protobuf.count else { throw LibP2PIdentityError.invalidProtobuf }
                keyData = Array(protobuf[offset..<end])
                offset = end
            default:
                throw LibP2PIdentityError.invalidProtobuf
            }
        }

        guard let raw = rawKeyType, let data = keyData else {
            throw LibP2PIdentityError.invalidProtobuf
        }
        guard let keyType = KeyType(rawValue: raw) else {
            throw LibP2PIdentityError.unknownKeyType(raw)
        }
        return (keyType, data)
    }

    /// Minimal unsigned-varint (LEB128) decode bounded to 10 octets.
    private static func decodeVarint(
        _ bytes: [UInt8], at offset: Int
    ) throws(LibP2PIdentityError) -> (value: UInt64, bytesRead: Int) {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        var index = offset
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if shift >= 63 && byte > 1 {
                throw LibP2PIdentityError.invalidProtobuf
            }
            value |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 {
                return (value, index - offset)
            }
            shift += 7
            if index - offset >= 10 {
                throw LibP2PIdentityError.invalidProtobuf
            }
        }
        throw LibP2PIdentityError.invalidProtobuf
    }

    // MARK: SignedKey verification

    /// Verifies the SignedKey signature over `"libp2p-tls-handshake:" || spkiDER`
    /// using the decoded identity public key.
    ///
    /// Crypto is injected: `verifyEd25519`/`verifyP256DER` receive
    /// `(publicKeyBytes, signature, message)` and return whether the signature
    /// is valid. The P-256 signature is DER-encoded (the libp2p convention);
    /// Ed25519 is the raw 64-byte signature. secp256k1 / RSA throw
    /// `.unsupportedKeyType` (no fallback).
    public static func verifySignedKey(
        protobufPubKey: [UInt8],
        signature: [UInt8],
        spkiDER: [UInt8],
        verifyEd25519: (_ publicKey: [UInt8], _ signature: [UInt8], _ message: [UInt8]) -> Bool,
        verifyP256DER: (_ publicKey: [UInt8], _ signature: [UInt8], _ message: [UInt8]) -> Bool
    ) throws(LibP2PIdentityError) -> Bool {
        let (keyType, keyBytes) = try decodePublicKey(protobufPubKey)
        let message = signatureMessage(spkiDER: spkiDER)
        switch keyType {
        case .ed25519:
            return verifyEd25519(keyBytes, signature, message)
        case .ecdsa:
            return verifyP256DER(keyBytes, signature, message)
        case .secp256k1, .rsa:
            throw LibP2PIdentityError.unsupportedKeyType(keyType)
        }
    }

    /// The libp2p TLS signature message: ASCII `"libp2p-tls-handshake:"` || SPKI DER.
    public static func signatureMessage(spkiDER: [UInt8]) -> [UInt8] {
        // "libp2p-tls-handshake:" (21 ASCII bytes), spelled out to avoid String.
        let prefix: [UInt8] = [
            0x6C, 0x69, 0x62, 0x70, 0x32, 0x70, 0x2D, // "libp2p-"
            0x74, 0x6C, 0x73, 0x2D,                   // "tls-"
            0x68, 0x61, 0x6E, 0x64, 0x73, 0x68, 0x61, 0x6B, 0x65, // "handshake"
            0x3A,                                     // ":"
        ]
        var out = [UInt8]()
        out.reserveCapacity(prefix.count + spkiDER.count)
        out.append(contentsOf: prefix)
        out.append(contentsOf: spkiDER)
        return out
    }

    // MARK: PeerID derivation

    /// Derives the PeerID multihash from the protobuf-encoded public key.
    ///
    /// Ed25519 keys with protobuf form <= 42 bytes use an identity multihash
    /// (`00 <varint len> <protobuf>`); all others use a SHA-256 multihash
    /// (`12 20 <SHA-256(protobuf)>`). The SHA-256 digest is injected via
    /// `sha256` (Embedded-clean: no `import Crypto`). No silent fallback —
    /// unknown key types throw.
    public static func peerIDMultihash(
        protobufPubKey: [UInt8],
        sha256: (_ data: [UInt8]) -> [UInt8]
    ) throws(LibP2PIdentityError) -> [UInt8] {
        let (keyType, _) = try decodePublicKey(protobufPubKey)
        if keyType.supportsIdentityEncoding && protobufPubKey.count <= identityEncodingMaxLength {
            return identityMultihash(protobufPubKey)
        }
        let digest = sha256(protobufPubKey)
        return sha256Multihash(digest)
    }

    /// `00 <varint len> <bytes>` — identity multihash framing.
    static func identityMultihash(_ bytes: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        out.append(0x00)                       // code: identity
        out.append(contentsOf: encodeVarint(UInt64(bytes.count)))
        out.append(contentsOf: bytes)
        return out
    }

    /// `12 20 <digest>` — SHA-256 multihash framing (code 0x12, len 0x20).
    static func sha256Multihash(_ digest: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        out.append(0x12)                       // code: sha2-256
        out.append(contentsOf: encodeVarint(UInt64(digest.count)))
        out.append(contentsOf: digest)
        return out
    }

    /// Minimal unsigned-varint (LEB128) encode.
    static func encodeVarint(_ value: UInt64) -> [UInt8] {
        var result = [UInt8]()
        var n = value
        while n >= 0x80 {
            result.append(UInt8(n & 0x7F) | 0x80)
            n >>= 7
        }
        result.append(UInt8(n))
        return result
    }
}
