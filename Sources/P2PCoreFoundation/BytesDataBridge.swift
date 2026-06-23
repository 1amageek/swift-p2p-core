// DataBytesBridge.swift
// Foundation <-> P2PCoreBytes interop for the migration period ONLY.
//
// This target intentionally imports Foundation and is NOT Embedded-compilable.
// It exists so existing Foundation/`Data`-based code can exchange bytes with the
// Embedded-clean core. The core `P2PCoreBytes` target must never import Foundation.

import Foundation
import P2PCoreBytes

extension Bytes {
    /// Creates a ``Bytes`` value by copying a Foundation `Data`.
    @inlinable
    public init(_ data: Data) {
        self.init([UInt8](data))
    }

    /// Returns the contents as a Foundation `Data` copy.
    ///
    /// Use only at the boundary with Foundation-based code; the core itself
    /// stays Foundation-free.
    @inlinable
    public var data: Data {
        Data(self.toArray())
    }
}

extension Data {
    /// Returns the contents as a ``Bytes`` value copy.
    @inlinable
    public var coreBytes: Bytes {
        Bytes(self)
    }
}
