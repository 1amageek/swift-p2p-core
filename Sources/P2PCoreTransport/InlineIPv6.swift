// InlineIPv6.swift
// Foundation-free 16-octet IPv6 address payload. Embedded-clean: no heap.

/// A fixed 16-byte IPv6 address payload that does not allocate.
///
/// Stored as named octets so the type stays a trivial, `Sendable`, `Hashable`
/// value usable under Embedded Swift (no heap, no Foundation). Bytes are in
/// network order.
public struct InlineIPv6: Sendable, Hashable {
    public var b0: UInt8,  b1: UInt8,  b2: UInt8,  b3: UInt8
    public var b4: UInt8,  b5: UInt8,  b6: UInt8,  b7: UInt8
    public var b8: UInt8,  b9: UInt8,  b10: UInt8, b11: UInt8
    public var b12: UInt8, b13: UInt8, b14: UInt8, b15: UInt8

    @inlinable
    public init(
        _ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8,
        _ b4: UInt8, _ b5: UInt8, _ b6: UInt8, _ b7: UInt8,
        _ b8: UInt8, _ b9: UInt8, _ b10: UInt8, _ b11: UInt8,
        _ b12: UInt8, _ b13: UInt8, _ b14: UInt8, _ b15: UInt8
    ) {
        self.b0 = b0; self.b1 = b1; self.b2 = b2; self.b3 = b3
        self.b4 = b4; self.b5 = b5; self.b6 = b6; self.b7 = b7
        self.b8 = b8; self.b9 = b9; self.b10 = b10; self.b11 = b11
        self.b12 = b12; self.b13 = b13; self.b14 = b14; self.b15 = b15
    }

    /// Returns the 16 octets as an owned array in network order.
    @inlinable
    public func toArray() -> [UInt8] {
        [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15]
    }
}
