// swift-tools-version: 6.2
// REQUIRED: platforms .v26 needs PackageDescription 6.2 (N3)
import PackageDescription

// Embedded toggle controls the experimental Embedded feature + WMO.
// Lifetimes is enabled in BOTH modes: Span-returning members need @_lifetime (A1).
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

// Host-only interop cross-check target depends on swift-certificates + swift-crypto.
// It proves the minimal-DER path is byte-compatible with the existing X.509 path.
// Disabled under Embedded (P2P_CORE_EMBEDDED=1) so the Embedded build never
// resolves these non-Embedded packages; opt out on host with P2P_CORE_NO_INTEROP=1.
let interopEnabled = !embeddedEnabled && Context.environment["P2P_CORE_NO_INTEROP"] != "1"

let package = Package(
    name: "swift-p2p-core",
    platforms: [
        .macOS(.v26),   // REQUIRED for host: Array.span/Span/RawSpan are @available(macOS 26+) (N3)
        .iOS(.v26),
    ],
    products: [
        .library(name: "P2PCoreBytes",      targets: ["P2PCoreBytes"]),
        .library(name: "P2PCoreCrypto",     targets: ["P2PCoreCrypto"]),
        .library(name: "P2PCoreDER",        targets: ["P2PCoreDER"]),
        .library(name: "P2PCoreTransport",  targets: ["P2PCoreTransport"]),
        .library(name: "P2PCoreFoundation", targets: ["P2PCoreFoundation"]),
    ],
    dependencies: interopEnabled ? [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.1"),
    ] : [],
    targets: [
        // ---- Embedded-enabled core (dual-build: host + Embedded) ----
        .target(name: "P2PCoreBytes",
                swiftSettings: coreSettings),
        .target(name: "P2PCoreCrypto",
                dependencies: ["P2PCoreBytes"],
                swiftSettings: coreSettings),
        .target(name: "P2PCoreDER",
                dependencies: ["P2PCoreBytes"],
                swiftSettings: coreSettings),
        .target(name: "P2PCoreTransport",
                dependencies: ["P2PCoreBytes"],
                swiftSettings: coreSettings),

        // ---- Non-Embedded Foundation bridge (host-only, never compiled Embedded) ----
        .target(name: "P2PCoreFoundation",
                dependencies: ["P2PCoreBytes"]),

        // ---- Tests (host-only, default toolchain, may import Foundation/Testing) ----
        .testTarget(name: "P2PCoreBytesTests",      dependencies: ["P2PCoreBytes"]),
        .testTarget(name: "P2PCoreCryptoTests",     dependencies: ["P2PCoreCrypto"]),
        .testTarget(name: "P2PCoreDERTests",        dependencies: ["P2PCoreDER"]),
        .testTarget(name: "P2PCoreTransportTests",  dependencies: ["P2PCoreTransport"]),
        .testTarget(name: "P2PCoreFoundationTests", dependencies: ["P2PCoreFoundation", "P2PCoreBytes"]),
    ] + (interopEnabled ? [
        // ---- Host-only swift-certificates interop cross-check (NOT Embedded) ----
        .testTarget(name: "P2PCoreDERInteropTests",
                    dependencies: [
                        "P2PCoreDER",
                        .product(name: "X509", package: "swift-certificates"),
                        .product(name: "SwiftASN1", package: "swift-asn1"),
                        .product(name: "Crypto", package: "swift-crypto"),
                    ]),
    ] : [])
)
