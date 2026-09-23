# bifrost

Open a byte-stream to a machine identified by its public key, wherever it is on the internet, across
NATs, without knowing its address. Identity is an ed25519 public key (a `NodeId`): you address *who* a
peer is, not *where*. bifrost gives you the connection and nothing more; what you send over it is up to
you.

It carries the connection over its own backends: iroh (QUIC with NAT hole-punching), an in-process
backend for tests, and [quirk](https://github.com/theia-hq/quirk), a QUIC-shaped transport written from scratch over UDP.

**The name.** Bifröst is the burning rainbow bridge of Norse myth, the span that reaches from one
world to any other. This crate is the bridge to a peer: name a public key and it carries a
connection there.

> Experimental. APIs will change and it is not ready for production use.

## Add it as a dependency

Git-only for now, not published to crates.io. Point at the repo:

```toml
[dependencies]
bifrost = { git = "https://github.com/theia-hq/bifrost" }
bifrost-iroh = { git = "https://github.com/theia-hq/bifrost" }
```

## Compose a node, dial by key

Compose a transport with a discovery mechanism into a `Node`, then dial peers by identity:

```rust
use bifrost::{Node, NoDiscovery, Session};
use bifrost_iroh::Endpoint;

let node = Node::new(Endpoint::bind().await?, NoDiscovery);
let session = node.connect(peer_id).await?;
let (mut writer, mut reader) = session.open_bi().await?;
```

`Transport`, `Session`, and `Discovery` are the pluggable interfaces. Implement `Transport` to add a
backend; every backend declares its `Security` profile (`Sealed`, `Announced`, or `InProcess`) and is
held to the same byte-movement behaviour by the conformance suite, so a dial written against these
interfaces runs unchanged over any of them.

## The crates

| crate                 | role                                                                |
| --------------------- | ------------------------------------------------------------------- |
| `bifrost`             | facade: the connection API (`Node`, `Transport`, `Session`, `Discovery`) |
| `bifrost-core`        | identity: `NodeId`, an ed25519 public key with a crypto-suite tag   |
| `keystore`            | a node's secret key on disk: one file, plain or sealed under a passphrase |
| `bifrost-transport`   | the `Transport` and `Session` traits                                |
| `bifrost-iroh`        | transport backend over iroh (QUIC with NAT hole-punching)           |
| `bifrost-mem`         | in-process transport backend for hermetic tests                     |
| `bifrost-noise`       | a Noise handshake over an announced transport: proves the peer's key, encrypts the session |
| `bifrost-quirk`       | transport backend over [quirk](https://github.com/theia-hq/quirk), a QUIC-shaped transport written from scratch |
| `bifrost-mdns`        | discovery over mDNS on the local network                            |
| `bifrost-conformance` | transport-agnostic test suite every backend must pass               |
| `bifrost-wire`        | one-shot blob transfer over a stream, BLAKE3-verified end to end    |

This page describes the default branch.

## Things to know

- bifrost establishes the connection and hands you a byte-stream. It says nothing about what those bytes
  mean; that is the caller's protocol.
- Verified blob transfer lives in `bifrost-wire`, a sibling crate the facade re-exports as `bifrost::wire`.
- Transports are interchangeable in interface, not in security. iroh, an in-process backend, and quirk
  all pass the same conformance suite, but each declares its own `Security` profile (`Sealed`,
  `Announced`, or `InProcess`), and a consumer states the bound it needs: `PeerProven` to trust the
  peer's key, `Secure` to carry a secret. A transport that does not meet the bound does not compile in.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
