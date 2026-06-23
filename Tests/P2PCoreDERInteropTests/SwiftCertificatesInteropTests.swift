// SwiftCertificatesInteropTests.swift
// Host-only proof that the minimal-DER P2PCoreDER path is byte-compatible with
// the shipping swift-certificates X.509 path used by swift-libp2p.
//
// This mirrors LibP2PCertificate.generate (swift-certificates) inline — without
// depending on swift-libp2p — then asserts:
//   1. parseLeaf extracts the SAME SPKI + extension value swift-certificates emits.
//   2. P2PCoreDER's buildSelfSignedCert output parses identically with
//      swift-certificates' Certificate(derEncoded:).
//   3. The SPKI parseLeaf returns is the exact CertificateVerify/SignedKey message.

import Testing
import Foundation
import Crypto
import SwiftASN1
@preconcurrency import X509
@testable import P2PCoreDER

@Suite("swift-certificates interop")
struct SwiftCertificatesInteropTests {

    static let libp2pExtensionOID = try! ASN1ObjectIdentifier(elements: [1, 3, 6, 1, 4, 1, 53594, 1, 1])
    static let signaturePrefix = "libp2p-tls-handshake:"

    /// Builds a libp2p self-signed cert with swift-certificates (the existing path).
    static func makeReferenceCert(
        tlsKey: P256.Signing.PrivateKey,
        signedKeyExtension: [UInt8]
    ) throws -> (certDER: [UInt8], spkiDER: [UInt8]) {
        // SPKI as swift-certificates serializes it.
        let certPublicKey = Certificate.PublicKey(tlsKey.publicKey)
        var spkiSer = DER.Serializer()
        try certPublicKey.serialize(into: &spkiSer, withIdentifier: .sequence)
        let spkiDER = spkiSer.serializedBytes

        let ext = Certificate.Extension(
            oid: libp2pExtensionOID,
            critical: true,
            value: ArraySlice(signedKeyExtension)
        )
        var extensions = Certificate.Extensions()
        try extensions.append(ext)

        let now = Date()
        let cert = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: certPublicKey,
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(365 * 24 * 3600),
            issuer: DistinguishedName {},
            subject: DistinguishedName {},
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(tlsKey)
        )
        var ser = DER.Serializer()
        try cert.serialize(into: &ser)
        return (ser.serializedBytes, spkiDER)
    }

    /// Encodes the SignedKey extension via P2PCoreDER for use in both paths.
    static func makeSignedKey() -> (ext: [UInt8], protobuf: [UInt8], signature: [UInt8]) {
        // A plausible Ed25519-shaped protobuf + 64-byte signature.
        let protobuf = LibP2PIdentityTestSupport.ed25519Protobuf(key: [UInt8](repeating: 0xAB, count: 32))
        let signature = [UInt8](repeating: 0x5C, count: 64)
        let ext = LibP2PSignedKeyDER.encode(protobufPubKey: protobuf, signature: signature)
        return (ext, protobuf, signature)
    }

    // MARK: 1. swift-certificates cert -> P2PCoreDER.parseLeaf

    @Test func parseLeaf_extractsIdenticalSPKIandExtension_fromReferenceCert() throws {
        let tlsKey = P256.Signing.PrivateKey()
        let sk = Self.makeSignedKey()
        let (certDER, refSPKI) = try Self.makeReferenceCert(tlsKey: tlsKey, signedKeyExtension: sk.ext)

        let leaf = try LibP2PCertificateDER.parseLeaf(certDER)

        // The SPKI parseLeaf returns must equal swift-certificates' SPKI byte-for-byte.
        #expect(leaf.spkiDER == refSPKI)
        // The extension value must equal the SignedKey we put in.
        #expect(leaf.libp2pExtensionValue == sk.ext)

        // And the SPKI must round-trip through our SPKI codec.
        let parsedSPKI = try SubjectPublicKeyInfoDER.parse(leaf.spkiDER)
        #expect(parsedSPKI.curve == .p256)
        #expect(parsedSPKI.keyBytes == Array(tlsKey.publicKey.x963Representation))
    }

    @Test func signedKeyExtension_roundTripsViaReferencePath() throws {
        let tlsKey = P256.Signing.PrivateKey()
        let sk = Self.makeSignedKey()
        let (certDER, _) = try Self.makeReferenceCert(tlsKey: tlsKey, signedKeyExtension: sk.ext)

        let leaf = try LibP2PCertificateDER.parseLeaf(certDER)
        let extValue = try #require(leaf.libp2pExtensionValue)
        let (pb, sig) = try LibP2PSignedKeyDER.parse(extValue)
        #expect(pb == sk.protobuf)
        #expect(sig == sk.signature)
    }

    // MARK: 2. P2PCoreDER.buildSelfSignedCert -> swift-certificates parses it

    @Test func buildSelfSignedCert_parsesWithSwiftCertificates() throws {
        let tlsKey = P256.Signing.PrivateKey()
        let sk = Self.makeSignedKey()

        // SPKI exactly as swift-certificates serializes it (so SignedKey message matches).
        let certPublicKey = Certificate.PublicKey(tlsKey.publicKey)
        var spkiSer = DER.Serializer()
        try certPublicKey.serialize(into: &spkiSer, withIdentifier: .sequence)
        let spkiDER = spkiSer.serializedBytes

        var serial = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { serial[i] = UInt8.random(in: 0...255) }
        serial[0] &= 0x7F

        let now = Int64(Date().timeIntervalSince1970)
        let cert = try LibP2PCertificateDER.buildSelfSignedCert(
            spkiDER: spkiDER,
            signedKeyExtension: sk.ext,
            serial16: serial,
            notBefore: now - 3600,
            notAfter: now + 365 * 24 * 3600,
            signFn: { tbs in
                // P-256 ECDSA-SHA256 over the TBS -> DER signature.
                let signature = try tlsKey.signature(for: Data(tbs))
                return Array(signature.derRepresentation)
            }
        )

        // swift-certificates must parse our cert and find the extension + key.
        let parsed = try Certificate(derEncoded: cert)
        let ext = try #require(parsed.extensions[oid: Self.libp2pExtensionOID])
        #expect(Array(ext.value) == sk.ext)
        #expect(ext.critical)

        // SPKI from the parsed cert must equal what we embedded.
        var roundTripSer = DER.Serializer()
        try parsed.publicKey.serialize(into: &roundTripSer, withIdentifier: .sequence)
        #expect(roundTripSer.serializedBytes == spkiDER)
    }

    // MARK: 3. End-to-end: our cert -> our parseLeaf -> our SPKI codec

    @Test func ourCert_ourParseLeaf_endToEnd() throws {
        let tlsKey = P256.Signing.PrivateKey()
        let sk = Self.makeSignedKey()
        let certPublicKey = Certificate.PublicKey(tlsKey.publicKey)
        var spkiSer = DER.Serializer()
        try certPublicKey.serialize(into: &spkiSer, withIdentifier: .sequence)
        let spkiDER = spkiSer.serializedBytes

        var serial = [UInt8](repeating: 0x42, count: 16)
        serial[0] &= 0x7F
        let now = Int64(Date().timeIntervalSince1970)
        let cert = try LibP2PCertificateDER.buildSelfSignedCert(
            spkiDER: spkiDER, signedKeyExtension: sk.ext, serial16: serial,
            notBefore: now - 3600, notAfter: now + 86400,
            signFn: { tbs in Array(try tlsKey.signature(for: Data(tbs)).derRepresentation) }
        )
        let leaf = try LibP2PCertificateDER.parseLeaf(cert)
        #expect(leaf.spkiDER == spkiDER)
        #expect(leaf.libp2pExtensionValue == sk.ext)
    }
}

/// Minimal protobuf encoder shared by the interop suite (mirrors PublicKeyProtobuf.encode).
enum LibP2PIdentityTestSupport {
    static func ed25519Protobuf(key: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        out.append(0x08)
        out.append(contentsOf: LibP2PIdentity.encodeVarint(1))   // KeyType.ed25519
        out.append(0x12)
        out.append(contentsOf: LibP2PIdentity.encodeVarint(UInt64(key.count)))
        out.append(contentsOf: key)
        return out
    }
}
