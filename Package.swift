// swift-tools-version: 6.4
// REQUIRED: the Native/WASM/Embedded baseline is the pinned Swift 6.4 snapshot.
import PackageDescription

// Portable toggles keep target-only validation graphs free of host interop dependencies.
// Lifetimes is enabled in every mode: Span-returning members need @_lifetime (A1).
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"
let wasiEnabled = Context.environment["P2P_CORE_WASM"] == "1"
let portableEnabled = embeddedEnabled || wasiEnabled

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

// Host-only interop cross-check target depends on swift-certificates + swift-crypto.
// It proves the minimal-DER path is byte-compatible with the existing X.509 path.
// Disabled for both WASM modes so portable builds never resolve host-only packages;
// opt out independently on host with P2P_CORE_NO_INTEROP=1.
let interopEnabled = !portableEnabled && Context.environment["P2P_CORE_NO_INTEROP"] != "1"

let packageDependencies: [Package.Dependency] = [
    // The canonical Pure Swift mechanism and primitive implementation.
    .package(
        url: "https://github.com/1amageek/swift-ssl.git",
        from: "0.1.1"
    ),
] + (interopEnabled ? [
    // Interop tests remain host-only and are not part of the production graph.
    .package(
        url: "https://github.com/1amageek/swift-crypto.git",
        from: "4.5.2"
    ),
    .package(
        url: "https://github.com/1amageek/swift-certificates.git",
        from: "1.19.3"
    ),
    .package(
        url: "https://github.com/1amageek/swift-asn1.git",
        from: "1.7.2"
    ),
] : [])

let package = Package(
    name: "swift-p2p-core",
    platforms: [
        .macOS(.v26),   // REQUIRED for host: Array.span/Span/RawSpan are @available(macOS 26+) (N3)
        .iOS(.v26),
    ],
    products: [
        .library(name: "P2PCoreDER",        targets: ["P2PCoreDER"]),
        .library(name: "P2PCoreTransport",  targets: ["P2PCoreTransport"]),
        .library(name: "P2PCoreFoundation", targets: ["P2PCoreFoundation"]),
        .library(name: "P2PCrypto",         targets: ["P2PCrypto"]),
        .executable(
            name: "p2p-core-capability-validation",
            targets: ["P2PCoreCapabilityValidation"]
        ),
    ],
    dependencies: packageDependencies,
    targets: [
        // ---- Embedded-enabled core (dual-build: host + Embedded) ----
        .target(name: "P2PCoreDER",
                dependencies: [
                    .product(name: "P2PCoreBytes", package: "swift-ssl"),
                ],
                swiftSettings: coreSettings),
        .target(name: "P2PCoreTransport",
                dependencies: [
                    .product(name: "P2PCoreBytes", package: "swift-ssl"),
                ],
                swiftSettings: coreSettings),

        // ---- P2P crypto adapter (dual-build: host + WASM + Embedded) ----
        .target(
            name: "P2PCrypto",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-ssl"),
                .product(name: "P2PCoreCrypto", package: "swift-ssl"),
                "P2PCoreDER",
                .product(name: "SSLCore", package: "swift-ssl"),
                .product(name: "SSLCrypto", package: "swift-ssl"),
            ],
            path: "Sources/P2PCrypto",
            sources: ["DefaultCryptoProvider.swift", "SSLBackendProvider.swift"],
            swiftSettings: coreSettings
        ),
        .executableTarget(
            name: "P2PCoreCapabilityValidation",
            dependencies: [
                .product(name: "P2PCoreCrypto", package: "swift-ssl"),
                "P2PCoreDER",
                "P2PCrypto",
            ],
            swiftSettings: coreSettings
        ),

        // ---- Non-Embedded Foundation bridge (host-only, never compiled Embedded) ----
        .target(name: "P2PCoreFoundation",
                dependencies: [
                    .product(name: "P2PCoreBytes", package: "swift-ssl"),
                ]),

        // ---- Tests (host-only, default toolchain, may import Foundation/Testing) ----
        .testTarget(name: "P2PCoreDERTests",        dependencies: ["P2PCoreDER"]),
        .testTarget(name: "P2PCoreTransportTests",  dependencies: ["P2PCoreTransport"]),
        .testTarget(name: "P2PCoreFoundationTests", dependencies: ["P2PCoreFoundation"]),
        .testTarget(name: "P2PCryptoTests",         dependencies: ["P2PCrypto"]),
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
