# swift-p2p-core (retired)

This package has been retired. It no longer publishes products from `main`.
Historical releases remain available through existing Git tags.

```text
Former swift-p2p-core responsibility
├── protocol-neutral bytes and addresses -> swift-networking/NetworkingCore
├── clocks and instants                 -> swift-networking/NetworkingTime
├── datagram contracts                  -> swift-networking/NetworkingDatagram
├── cryptographic capability contracts  -> swift-ssl/SSLCryptoContracts
├── cryptographic implementations       -> swift-ssl/SSLCrypto
├── generic DER                         -> swift-ssl/SSLASN1
└── libp2p identity and certificate DER -> swift-libp2p/LibP2PCore
```

There is no compatibility product or runtime fallback. Consumers must import
the responsibility-specific replacement module directly. Source retained in
this checkout is historical and is not part of the package graph.
