// Hex.swift
// Test-only hex helpers.

enum Hex {
    static func decode(_ string: String) -> [UInt8] {
        let chars = Array(string.filter { !$0.isWhitespace })
        precondition(chars.count % 2 == 0, "hex string must have even length")
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var index = 0
        while index < chars.count {
            let hi = nibble(chars[index])
            let lo = nibble(chars[index + 1])
            out.append(UInt8(hi << 4 | lo))
            index += 2
        }
        return out
    }

    static func encode(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef")
        var output: [Character] = []
        output.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            output.append(digits[Int(byte >> 4)])
            output.append(digits[Int(byte & 0x0f)])
        }
        return String(output)
    }

    private static func nibble(_ c: Character) -> Int {
        switch c {
        case "0"..."9": return Int(c.asciiValue! - Character("0").asciiValue!)
        case "a"..."f": return Int(c.asciiValue! - Character("a").asciiValue! + 10)
        case "A"..."F": return Int(c.asciiValue! - Character("A").asciiValue! + 10)
        default: preconditionFailure("invalid hex char \(c)")
        }
    }
}

extension Array where Element == UInt8 {
    /// Runs `body` with a `Span<UInt8>` view of this array.
    func withSpan<R>(_ body: (Span<UInt8>) throws -> R) rethrows -> R {
        try body(self.span)
    }
}
