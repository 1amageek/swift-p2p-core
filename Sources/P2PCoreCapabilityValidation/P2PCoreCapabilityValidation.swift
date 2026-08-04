import P2PCoreCrypto
import P2PCoreDER
import P2PCrypto

@main
struct P2PCoreCapabilityValidation {
    static func main() {
        validateAuthenticatedEncryption()
        validateDigests()
        validateCanonicalECDSADER()
        print("P2P core capability validation passed")
    }

    private static func validateAuthenticatedEncryption() {
        let key = [UInt8](repeating: 0xA5, count: 16)
        let nonce = [UInt8](repeating: 0x11, count: 12)
        let authenticatedData: [UInt8] = [0x20, 0x21, 0x22, 0x23]
        let plaintext = [UInt8](repeating: 0x5A, count: 4_096)

        do {
            let aead = try DefaultAEAD(
                algorithm: .aes128gcm,
                key: key.span
            )
            let sealed = try aead.seal(
                plaintext.span,
                nonce: nonce.span,
                aad: authenticatedData.span
            )
            precondition(sealed.count == plaintext.count + DefaultAEAD.tagLength)
            let opened = try aead.open(
                sealed.span,
                nonce: nonce.span,
                aad: authenticatedData.span
            )
            precondition(opened == plaintext)

            var tampered = sealed
            tampered[tampered.count - 1] ^= 1
            do {
                _ = try aead.open(
                    tampered.span,
                    nonce: nonce.span,
                    aad: authenticatedData.span
                )
                preconditionFailure("AEAD accepted a corrupted tag")
            } catch CryptoError.authenticationFailure {
                // Expected fail-closed authentication result.
            } catch {
                preconditionFailure("AEAD returned the wrong failure")
            }
        } catch {
            preconditionFailure("AEAD capability validation failed")
        }
    }

    private static func validateDigests() {
        let message = Array("abc".utf8)
        let expectedSHA256: [UInt8] = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
            0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
            0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
            0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
        ]
        precondition(DefaultSHA256.hash(message.span) == expectedSHA256)

        let hmacKey = Array("Jefe".utf8)
        let hmacMessage = Array("what do ya want for nothing?".utf8)
        let expectedHMACSHA256: [UInt8] = [
            0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
            0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7,
            0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83,
            0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC, 0x38, 0x43,
        ]
        precondition(
            DefaultHMACSHA256.authenticationCode(
                for: hmacMessage.span,
                key: hmacKey.span
            ) == expectedHMACSHA256
        )

        let expectedHMACSHA1: [UInt8] = [
            0xEF, 0xFC, 0xDF, 0x6A, 0xE5, 0xEB, 0x2F, 0xA2,
            0xD2, 0x74, 0x16, 0xD5, 0xF1, 0x84, 0xDF, 0x9C,
            0x25, 0x9A, 0x7C, 0x79,
        ]
        precondition(
            DefaultHMACSHA1.authenticationCode(
                for: hmacMessage.span,
                key: hmacKey.span
            ) == expectedHMACSHA1
        )

        let expectedHMACSHA384: [UInt8] = [
            0xAF, 0x45, 0xD2, 0xE3, 0x76, 0x48, 0x40, 0x31,
            0x61, 0x7F, 0x78, 0xD2, 0xB5, 0x8A, 0x6B, 0x1B,
            0x9C, 0x7E, 0xF4, 0x64, 0xF5, 0xA0, 0x1B, 0x47,
            0xE4, 0x2E, 0xC3, 0x73, 0x63, 0x22, 0x44, 0x5E,
            0x8E, 0x22, 0x40, 0xCA, 0x5E, 0x69, 0xE2, 0xC7,
            0x8B, 0x32, 0x39, 0xEC, 0xFA, 0xB2, 0x16, 0x49,
        ]
        precondition(
            DefaultHMACSHA384.authenticationCode(
                for: hmacMessage.span,
                key: hmacKey.span
            ) == expectedHMACSHA384
        )

        let longKey = [UInt8](repeating: 0xAA, count: 80)
        let longKeyMessage = Array(
            "Test Using Larger Than Block-Size Key - Hash Key First".utf8
        )
        let expectedLongKeyHMACSHA1: [UInt8] = [
            0xAA, 0x4A, 0xE5, 0xE1, 0x52, 0x72, 0xD0, 0x0E,
            0x95, 0x70, 0x56, 0x37, 0xCE, 0x8A, 0x3B, 0x55,
            0xED, 0x40, 0x21, 0x12,
        ]
        precondition(
            DefaultHMACSHA1.authenticationCode(
                for: longKeyMessage.span,
                key: longKey.span
            ) == expectedLongKeyHMACSHA1
        )

        var incremental = DefaultHMACSHA384(key: hmacKey.span)
        let prefix = Array(hmacMessage.prefix(9))
        let suffix = Array(hmacMessage.dropFirst(9))
        incremental.update(prefix.span)
        incremental.update(suffix.span)
        precondition(
            incremental.finalize() == expectedHMACSHA384
        )
    }

    private static func validateCanonicalECDSADER() {
        var raw = [UInt8](repeating: 0, count: 64)
        raw[0] = 0x80
        raw[63] = 0x01

        do {
            let encoded = try ECDSASignatureDER.encode(
                rawRepresentation: raw,
                scalarByteCount: 32
            )
            let decoded = try ECDSASignatureDER.decode(
                derRepresentation: encoded,
                scalarByteCount: 32
            )
            precondition(decoded == raw)

            let nonCanonical: [UInt8] = [
                0x30, 0x07,
                0x02, 0x02, 0x00, 0x01,
                0x02, 0x01, 0x01,
            ]
            do {
                _ = try ECDSASignatureDER.decode(
                    derRepresentation: nonCanonical,
                    scalarByteCount: 32
                )
                preconditionFailure("Non-canonical DER was accepted")
            } catch DERError.nonMinimalInteger {
                // Expected strict DER rejection.
            } catch {
                preconditionFailure("DER decoder returned the wrong failure")
            }
        } catch {
            preconditionFailure("ECDSA DER capability validation failed")
        }
    }
}
