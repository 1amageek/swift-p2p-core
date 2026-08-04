// DefaultAESCounterModeTests.swift
// NIST vectors and reusable in-place contracts for AES-128-CTR.
import Testing
import P2PCoreCrypto
@testable import P2PCrypto

@Suite("Default AES-128-CTR")
struct DefaultAESCounterModeTests {
    private let key = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c")
    private let counter = Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    private let firstPlaintext = Hex.decode("6bc1bee22e409f96e93d7e117393172a")
    private let firstCiphertext = Hex.decode("874d6191b620e3261bef6864990db6ce")

    @Test func nistSP80038AFullVector() throws {
        let plaintext = Hex.decode(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        let expected = Hex.decode(
            "874d6191b620e3261bef6864990db6ce" +
            "9806f66b7970fdff8617187bb9fffdff" +
            "5ae4df3edbd5d35e5b4f09020db03eab" +
            "1e031dda2fbe03d1792170a0f3009cee"
        )
        let cipher = try DefaultCryptoProvider.makeAES128CounterMode(key: key.span)
        var result = plaintext
        let range = result.indices

        try cipher.applyKeystream(
            to: &result,
            range: range,
            initialCounter: counter.span
        )

        #expect(result == expected)
    }

    @Test func resetSupportsDifferentAndRepeatedCounters() throws {
        let secondCounter = Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdff00")
        let secondPlaintext = Hex.decode("ae2d8a571e03ac9c9eb76fac45af8e51")
        let secondCiphertext = Hex.decode("9806f66b7970fdff8617187bb9fffdff")
        let cipher = try DefaultAES128CounterMode(key: key.span)
        var first = firstPlaintext
        var second = secondPlaintext
        let firstRange = first.indices
        let secondRange = second.indices

        try cipher.applyKeystream(to: &first, range: firstRange, initialCounter: counter.span)
        try cipher.applyKeystream(to: &second, range: secondRange, initialCounter: secondCounter.span)
        #expect(first == firstCiphertext)
        #expect(second == secondCiphertext)

        try cipher.applyKeystream(to: &first, range: firstRange, initialCounter: counter.span)
        #expect(first == firstPlaintext)
    }

    @Test func rangeMutationPreservesSentinelsAndRoundTrips() throws {
        let cipher = try DefaultAES128CounterMode(key: key.span)
        var packet: [UInt8] = [0xA5] + firstPlaintext + [0x5A]
        let payloadRange = 1..<(1 + firstPlaintext.count)

        try cipher.applyKeystream(to: &packet, range: payloadRange, initialCounter: counter.span)
        #expect(packet.first == 0xA5)
        #expect(Array(packet[payloadRange]) == firstCiphertext)
        #expect(packet.last == 0x5A)

        try cipher.applyKeystream(to: &packet, range: payloadRange, initialCounter: counter.span)
        #expect(Array(packet[payloadRange]) == firstPlaintext)
    }

    @Test func sharedContextSupportsConcurrentIndependentOperations() async throws {
        let cipher = try DefaultAES128CounterMode(key: key.span)
        let input = firstPlaintext
        let expected = firstCiphertext
        let initialCounter = counter

        let outputs = try await withThrowingTaskGroup(of: [UInt8].self) { group in
            for _ in 0..<16 {
                group.addTask {
                    var result = input
                    let range = result.indices
                    try cipher.applyKeystream(
                        to: &result,
                        range: range,
                        initialCounter: initialCounter.span
                    )
                    return result
                }
            }

            var results: [[UInt8]] = []
            for try await result in group {
                results.append(result)
            }
            return results
        }

        #expect(outputs.count == 16)
        #expect(outputs.allSatisfy { $0 == expected })
    }

    @Test func invalidInputsAreTypedFailures() throws {
        let shortKey = [UInt8](repeating: 0, count: 15)
        #expect(throws: AESCounterModeError.invalidKeyLength(expected: 16, actual: 15)) {
            _ = try DefaultAES128CounterMode(key: shortKey.span)
        }

        let cipher = try DefaultAES128CounterMode(key: key.span)
        let shortCounter = [UInt8](repeating: 0, count: 15)
        var packet = [UInt8](repeating: 0, count: 8)
        let validRange = packet.indices
        #expect(throws: AESCounterModeError.invalidCounterLength(expected: 16, actual: 15)) {
            try cipher.applyKeystream(
                to: &packet,
                range: validRange,
                initialCounter: shortCounter.span
            )
        }
        #expect(throws: AESCounterModeError.invalidRange(lowerBound: 1, upperBound: 9, bufferCount: 8)) {
            try cipher.applyKeystream(
                to: &packet,
                range: 1..<9,
                initialCounter: counter.span
            )
        }
    }
}
