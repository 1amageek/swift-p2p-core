// DERReader.swift
// A strict-DER TLV cursor over owned [UInt8] storage. ~Copyable single-owner
// read position (no aliasing). Rejects BER indefinite length, non-minimal
// lengths, and trailing garbage inside descended constructed bodies. Typed
// throws(DERError) everywhere — never traps on wire data, never silently
// accepts. Embedded-clean: no Foundation, no `any`.

import P2PCoreBytes

/// A bounds-checked, strict-DER reader.
///
/// The reader owns its storage as `[UInt8]` (copied from the source view on
/// init) and tracks a single-owner cursor. It is `~Copyable` so the read
/// position cannot be accidentally aliased. Every primitive validates remaining
/// bytes and throws a typed ``DERError`` instead of trapping.
public struct DERReader: ~Copyable {

    @usableFromInline let storage: [UInt8]
    @usableFromInline var cursor: Int

    // MARK: Inits

    /// Creates a reader over an owned array.
    @inlinable public init(_ bytes: [UInt8]) {
        self.storage = bytes
        self.cursor = 0
    }

    /// Creates a reader by copying a borrowed typed view into owned storage.
    public init(_ span: Span<UInt8>) {
        var array = [UInt8]()
        array.reserveCapacity(span.count)
        for index in 0..<span.count {
            array.append(span[index])
        }
        self.storage = array
        self.cursor = 0
    }

    // MARK: State

    /// Whether the cursor has reached the end of the buffer.
    @inlinable public var isAtEnd: Bool { cursor >= storage.count }

    /// Number of unread bytes remaining.
    @inlinable public var remaining: Int { storage.count - cursor }

    /// A borrowed typed view over the unread tail (P5: borrowing get + @_lifetime).
    public var remainingSpan: Span<UInt8> {
        @_lifetime(borrow self)
        borrowing get { storage.span.extracting(cursor..<storage.count) }
    }

    // MARK: Low-level primitives

    /// Reads one identifier (tag) octet.
    @usableFromInline
    mutating func readTagByte() throws(DERError) -> UInt8 {
        guard remaining >= 1 else { throw DERError.truncated }
        let tag = storage[cursor]
        cursor += 1
        return tag
    }

    /// Reads a strict-DER length: short form (< 128), or long form (minimal,
    /// no leading 0x00, no value < 128 encoded long, no `Int` overflow). The
    /// returned length is guaranteed `<= remaining` after this call.
    @usableFromInline
    mutating func readLength() throws(DERError) -> Int {
        guard remaining >= 1 else { throw DERError.truncated }
        let first = storage[cursor]
        cursor += 1

        if first < 0x80 {
            let length = Int(first)
            guard length <= remaining else { throw DERError.truncated }
            return length
        }
        if first == 0x80 {
            throw DERError.indefiniteLength
        }

        let octetCount = Int(first & 0x7F)
        // octetCount >= 1 here (first > 0x80).
        guard remaining >= octetCount else { throw DERError.truncated }

        // Reject leading 0x00 length octet (non-minimal).
        if storage[cursor] == 0x00 {
            throw DERError.nonMinimalLength
        }
        // More than 8 octets cannot fit a non-negative Int.
        if octetCount > 8 {
            throw DERError.badLength
        }

        var value = 0
        var index = 0
        while index < octetCount {
            let byte = Int(storage[cursor + index])
            // Guard against Int overflow before the shift-or.
            if value > (Int.max >> 8) {
                throw DERError.badLength
            }
            value = (value << 8) | byte
            index += 1
        }
        cursor += octetCount

        // Long form must not encode a value representable in short form.
        if value < 128 {
            throw DERError.nonMinimalLength
        }
        guard value <= remaining else { throw DERError.truncated }
        return value
    }

    /// Reads `count` content bytes as an owned array (cursor advances).
    @usableFromInline
    mutating func readContent(_ count: Int) throws(DERError) -> [UInt8] {
        guard count >= 0, remaining >= count else { throw DERError.truncated }
        var result = [UInt8]()
        result.reserveCapacity(count)
        let end = cursor + count
        var index = cursor
        while index < end {
            result.append(storage[index])
            index += 1
        }
        cursor = end
        return result
    }

    // MARK: Public TLV reads

    /// Reads tag + length, returns the tag byte and the content as owned bytes.
    /// (Embedded-safe: owned bytes cross the ~Copyable boundary cleanly.)
    public mutating func readTLV() throws(DERError) -> (tag: UInt8, content: [UInt8]) {
        let tag = try readTagByte()
        let length = try readLength()
        let content = try readContent(length)
        return (tag, content)
    }

    /// Non-consuming peek at the next identifier octet, or `nil` at end of input.
    public func peekTag() -> UInt8? {
        guard cursor < storage.count else { return nil }
        return storage[cursor]
    }

    // MARK: Typed expecters

    /// Expects `tag`, descends into the content as a child reader, runs `body`,
    /// then requires the child fully consumed (`.trailingBytes` otherwise).
    public mutating func readConstructed<R>(
        _ tag: DERTag,
        _ body: (inout DERReader) throws(DERError) -> R
    ) throws(DERError) -> R {
        let found = try readTagByte()
        guard found == tag.rawValue else {
            throw DERError.unexpectedTag(found: found, wanted: tag.rawValue)
        }
        let length = try readLength()
        let content = try readContent(length)
        var child = DERReader(content)
        let result = try body(&child)
        guard child.isAtEnd else { throw DERError.trailingBytes }
        return result
    }

    /// Reads a primitive TLV of an expected tag, returning its content.
    @usableFromInline
    mutating func readExpected(_ tag: DERTag) throws(DERError) -> [UInt8] {
        let found = try readTagByte()
        guard found == tag.rawValue else {
            throw DERError.unexpectedTag(found: found, wanted: tag.rawValue)
        }
        let length = try readLength()
        return try readContent(length)
    }

    /// Reads an OCTET STRING (tag `0x04`).
    public mutating func readOctetString() throws(DERError) -> [UInt8] {
        try readExpected(.octetString)
    }

    /// Reads a BIT STRING (tag `0x03`); requires the unused-bits octet == 0x00.
    public mutating func readBitString() throws(DERError) -> [UInt8] {
        let content = try readExpected(.bitString)
        guard let unused = content.first else { throw DERError.bitStringEmpty }
        guard unused == 0x00 else { throw DERError.nonZeroBitStringPadding(unused) }
        return Array(content.dropFirst())
    }

    /// Reads an OBJECT IDENTIFIER (tag `0x06`); returns content bytes verbatim.
    public mutating func readOID() throws(DERError) -> ObjectID {
        ObjectID(try readExpected(.objectIdentifier))
    }

    /// Reads an INTEGER (tag `0x02`); returns content as-is (sign byte preserved).
    public mutating func readIntegerBytes() throws(DERError) -> [UInt8] {
        let content = try readExpected(.integer)
        guard !content.isEmpty else { throw DERError.integerEmpty }
        return content
    }

    /// Reads a BOOLEAN (tag `0x01`); DER true == 0xFF (any non-zero accepted as
    /// true here is rejected — strict DER requires exactly 0x00 or 0xFF).
    public mutating func readBoolean() throws(DERError) -> Bool {
        let content = try readExpected(.boolean)
        guard content.count == 1 else { throw DERError.malformedBoolean }
        switch content[0] {
        case 0x00: return false
        case 0xFF: return true
        default: throw DERError.malformedBoolean
        }
    }

    /// Consumes exactly one TLV of any tag without interpreting it.
    public mutating func skip() throws(DERError) {
        _ = try readTagByte()
        let length = try readLength()
        guard length <= remaining else { throw DERError.truncated }
        cursor += length
    }

    /// Returns the raw bytes of the next TLV (tag+len+content) without
    /// interpreting it, advancing past it. Used to capture SPKI verbatim.
    public mutating func captureRawTLV() throws(DERError) -> [UInt8] {
        let start = cursor
        _ = try readTagByte()
        let length = try readLength()
        guard length <= remaining else { throw DERError.truncated }
        cursor += length
        var result = [UInt8]()
        result.reserveCapacity(cursor - start)
        var index = start
        while index < cursor {
            result.append(storage[index])
            index += 1
        }
        return result
    }
}
