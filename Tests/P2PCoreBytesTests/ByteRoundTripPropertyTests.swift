// ByteRoundTripPropertyTests.swift
// Property / fuzz tests: untrusted-wire safety (no traps), writer/reader identity,
// and varint encode/decode identity across all classes.

import Testing
@testable import P2PCoreBytes

@Suite("Byte round-trip / fuzz")
struct ByteRoundTripPropertyTests {
    /// A small deterministic xorshift PRNG so the fuzz corpus is reproducible
    /// without depending on Foundation.
    struct XorShift64 {
        var state: UInt64
        init(seed: UInt64) { self.state = seed == 0 ? 0x9E3779B97F4A7C15 : seed }
        mutating func next() -> UInt64 {
            var x = state
            x ^= x << 13
            x ^= x >> 7
            x ^= x << 17
            state = x
            return x
        }
        mutating func byte() -> UInt8 { UInt8(truncatingIfNeeded: next()) }
        mutating func int(_ bound: Int) -> Int { bound <= 0 ? 0 : Int(next() % UInt64(bound)) }
    }

    @Test func fuzz_randomBuffer_everyReadMethod_neverTraps_onlyTypedThrows() {
        var rng = XorShift64(seed: 0xC0FFEE)
        for iteration in 0..<500 {
            let length = rng.int(40)
            var buffer = [UInt8]()
            buffer.reserveCapacity(length)
            for _ in 0..<length { buffer.append(rng.byte()) }

            // Each read method must either succeed or throw a typed ByteError.
            // A trap would crash the test process, so reaching the end is the
            // guarantee. We rotate through methods based on the iteration.
            var reader = ByteReader(buffer)
            do {
                switch iteration % 11 {
                case 0:  _ = try reader.readUInt8()
                case 1:  _ = try reader.readUInt16()
                case 2:  _ = try reader.readUInt24()
                case 3:  _ = try reader.readUInt32()
                case 4:  _ = try reader.readUInt64()
                case 5:  _ = try reader.readVarint()
                case 6:  _ = try reader.readVector8()
                case 7:  _ = try reader.readVector16()
                case 8:  _ = try reader.readVector24()
                case 9:  _ = try reader.readVarintVector()
                default: _ = try reader.skip(rng.int(64))
                }
            } catch {
                // Any thrown error is, by construction, a typed ByteError.
                _ = error
            }
            // readRemaining never traps and never throws.
            _ = reader.readRemaining()
        }
        #expect(Bool(true))
    }

    @Test func property_writerThenReader_isIdentity_forRandomStructuredInput() throws {
        var rng = XorShift64(seed: 0x1234_5678)
        for _ in 0..<200 {
            let u8 = rng.byte()
            let u16 = UInt16(truncatingIfNeeded: rng.next())
            let u32 = UInt32(truncatingIfNeeded: rng.next())
            let u64 = rng.next()
            let vecLen = rng.int(50)
            var vec = [UInt8]()
            for _ in 0..<vecLen { vec.append(rng.byte()) }

            var w = ByteWriter()
            w.writeUInt8(u8)
            w.writeUInt16(u16)
            w.writeUInt32(u32)
            w.writeUInt64(u64)
            try w.writeVector16(vec)

            var r = ByteReader(w.finishArray())
            #expect(try r.readUInt8() == u8)
            #expect(try r.readUInt16() == u16)
            #expect(try r.readUInt32() == u32)
            #expect(try r.readUInt64() == u64)
            #expect(try r.readVector16() == vec)
            #expect(r.isAtEnd == true)
        }
    }

    @Test func property_varint_encodeDecode_isIdentity_acrossClasses() throws {
        let values: [UInt64] = [
            0, 1, 62, 63, 64, 16382, 16383, 16384,
            1_073_741_822, 1_073_741_823, 1_073_741_824,
            (UInt64(1) << 62) - 2, (UInt64(1) << 62) - 1,
        ]
        for value in values {
            var w = ByteWriter()
            try w.writeVarint(value)
            var r = ByteReader(w.finishArray())
            #expect(try r.readVarint() == value)
            #expect(r.isAtEnd == true)
        }
    }
}
