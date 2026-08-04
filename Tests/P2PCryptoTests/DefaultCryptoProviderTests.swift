import P2PCoreCrypto
import Testing
@testable import P2PCrypto

@Suite("Default crypto provider")
struct DefaultCryptoProviderTests {
    @Test func aesCounterModeExecutesThroughDefaultProvider() throws {
        let key = [UInt8](repeating: 0, count: 16)
        let counter = [UInt8](repeating: 0, count: 16)
        var payload = [UInt8](repeating: 0, count: 16)
        let cipher = try DefaultCryptoProvider.makeAES128CounterMode(
            key: key.span
        )

        try cipher.applyKeystream(
            to: &payload,
            range: payload.indices,
            initialCounter: counter.span
        )

        #expect(payload == [
            0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B,
            0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E,
        ])
    }
}
