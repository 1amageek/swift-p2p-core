// IPAddress.swift
// Foundation-free IP address value type (IPv4 / IPv6). Embedded-clean.

/// An IP address held as raw bytes, with no dependency on Foundation or POSIX
/// `sockaddr` types.
///
/// IPv4 holds 4 bytes in network order; IPv6 holds 16 bytes in network order.
/// Concrete transports (M5) convert to/from `sockaddr` at the syscall boundary.
public enum IPAddress: Sendable, Hashable {
    /// An IPv4 address: 4 bytes in network byte order.
    case v4(UInt8, UInt8, UInt8, UInt8)

    /// An IPv6 address: 16 bytes in network byte order.
    case v6(InlineIPv6)

    /// The raw address bytes in network order (4 for IPv4, 16 for IPv6).
    @inlinable
    public var rawBytes: [UInt8] {
        switch self {
        case let .v4(a, b, c, d):
            return [a, b, c, d]
        case let .v6(octets):
            return octets.toArray()
        }
    }

    /// Whether this is an IPv4 address.
    @inlinable
    public var isIPv4: Bool {
        if case .v4 = self { return true }
        return false
    }
}
