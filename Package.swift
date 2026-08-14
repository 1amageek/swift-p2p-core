// swift-tools-version: 6.4

import PackageDescription

// This package is intentionally empty. Its protocol-neutral byte, time, and
// datagram contracts moved to swift-networking; cryptographic contracts moved
// to swift-ssl; libp2p-specific identity DER moved to swift-libp2p. Existing
// release tags remain available for historical builds. No compatibility
// products are published from main.
let package = Package(name: "swift-p2p-core")
