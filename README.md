# swift-p2p-core

Embedded-first foundation for a Swift libp2p stack. It defines the byte
currency, the crypto capability protocols, a strict-DER codec, and the
datagram transport seam that the rest of the stack builds on — with zero
`any` existentials and zero Foundation in the core modules.

## Status

This package has no git remote and no released tag yet (first release is
gated behind milestone M8). Until then, depend on it via a local path:

```swift
.package(path: "../swift-p2p-core")
```

No version or URL is published; do not pin a tag that does not exist.

## Products

| Product | Target deps | Purpose |
|---|---|---|
| `P2PCoreBytes` | — | Byte currency: `Bytes`, `ByteReader`, `ByteWriter`, `ByteError` |
| `P2PCoreCrypto` | `P2PCoreBytes` | `CryptoProvider` capability protocols + clock/timer seams |
| `P2PCoreDER` | `P2PCoreBytes` | Strict minimal-DER reader/writer + SPKI / SignedKey / certificate codecs |
| `P2PCoreTransport` | `P2PCoreBytes` | `DatagramTransport` seam, endpoints, IP address types |
| `P2PCoreFoundation` | `P2PCoreBytes` | Host bridge: `Bytes` ↔ `Data` (Foundation, host-only) |

Every product is one library backed by one same-named target.

## Byte currency

`P2PCoreBytes` provides `Bytes`, an owned value type wrapping `[UInt8]`
storage. Borrowed, zero-copy views are exposed on demand as `Span<UInt8>` /
`RawSpan` (returned with `@_lifetime(borrow self)`, never stored). The wire
and algorithmic currency across the stack is `[UInt8]`; `Span<UInt8>` is the
zero-copy borrow used at protocol boundaries. The `Lifetimes` experimental
feature is always enabled so Span-returning members can express their
lifetime.

## Crypto capabilities

`CryptoProvider` (in `P2PCoreCrypto`) is decomposed into capability
sub-protocols rather than one monolith. The aggregate composes:

| Sub-protocol | Capability |
|---|---|
| `AEADProvider` | AES-GCM-128/256, ChaCha20-Poly1305 |
| `KDFProvider` (refines `HashProvider`) | HKDF-SHA256 / HKDF-SHA384 |
| `MACProvider` | HMAC-SHA1 / SHA256 / SHA384 |
| `KeyAgreementProvider` | X25519, P-256, P-384 ECDH |
| `SignatureProvider` | Ed25519, P-256, P-384 signatures |
| `EntropyProvider` | CSPRNG (`associatedtype Random: RandomSource`) |
| `ClockProvider` | monotonic clock singleton (`associatedtype Clock: MonotonicClock`) |
| `HeaderProtectionProviding` | QUIC header protection (RFC 9001 §5.4) |

`HashProvider` is the hashing primitive that `KDFProvider` refines.
Capabilities are expressed as `associatedtype`s (no `any`), and operations
use typed throws (`throws(CryptoError)`). Concrete providers live in
`swift-p2p-crypto`.

## Clock and timer seams

The core inverts time so Embedded builds need neither `Task.sleep` nor
`ContinuousClock`:

```swift
public protocol MonotonicClock: Sendable {
    func monotonicMillis() -> UInt64
    func monotonicNanos() -> UInt64
}

public protocol AsyncTimer: MonotonicClock {
    func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError)
}
```

`AsyncTimer` refines `MonotonicClock` (one clock source) and throws only
`CancellationError` (a typed throw — untyped `throws` would erase to
`any Error` across the async boundary, which Embedded rejects). Concrete
timer implementations are provided downstream (e.g. `swift-p2p-transport`).

## DER codec

`P2PCoreDER` is a strict, minimal-DER toolkit over owned `[UInt8]` (and
`Span<UInt8>`):

- `DERReader` (`~Copyable`) — strict TLV cursor; rejects BER indefinite
  length, non-minimal length, and trailing bytes; reads throw `DERError`
  rather than trapping on hostile wire data.
- `DERWriter` — append-oriented minimal-DER builder.
- `ObjectID` — fixed OID constants (`ecPublicKey`, `secp256r1`,
  `secp384r1`, `ed25519`, `libp2pExt`).
- `SubjectPublicKeyInfoDER` — SPKI encode/parse for P-256, P-384, Ed25519.
- `LibP2PSignedKeyDER` — libp2p SignedKey extension value codec.
- `LibP2PCertificateDER` — self-signed leaf certificate builder/parser.
- `LibP2PIdentity` — public-key decode, signed-key verification, and PeerID
  multihash derivation.

The libp2p TLS extension OID is `1.3.6.1.4.1.53594.1.1`, exposed as
`ObjectID.libp2pExt`.

## Embedded-first build

The core modules (`P2PCoreBytes`, `P2PCoreCrypto`, `P2PCoreDER`,
`P2PCoreTransport`) carry no `any` existentials and no Foundation imports,
so they compile under Embedded Swift. The build is dual-mode, gated on the
`P2P_CORE_EMBEDDED` environment variable:

```bash
# Host build (default): Lifetimes only
swift build

# Embedded build: adds Embedded feature + whole-module optimization
P2P_CORE_EMBEDDED=1 swift build
```

`P2PCoreFoundation` is the host-only bridge and is excluded from the
Embedded core. Host builds also run `P2PCoreDERInteropTests`, which
cross-check the minimal-DER output against Apple's X.509 / ASN.1 / Crypto
packages; that interop suite can be opted out with `P2P_CORE_NO_INTEROP=1`
and is automatically excluded under `P2P_CORE_EMBEDDED=1`.

## Requirements

- Swift 6.2+ (tools version `6.2`)
- macOS 26+ / iOS 26+ (for `Span` / `RawSpan` availability)
