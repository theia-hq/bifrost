# bifrost

Open a byte-stream to a machine identified by its public key, wherever it is on the internet, across
NATs, without knowing its address. Identity is an ed25519 public key (a `NodeId`): you address *who* a
peer is, not *where*. bifrost gives you the connection and nothing more; what you send over it is up to
you.

> Experimental. APIs will change and it is not ready for production use.

## Usage

Compose a transport with a discovery mechanism into a `Node`, then dial peers by identity:

```rust
use bifrost::{Node, NoDiscovery, Session};

let node = Node::new(transport, NoDiscovery);
let session = node.connect(peer_id).await?;
let (mut writer, mut reader) = session.open_bi().await?;
```

`Transport`, `Session`, and `Discovery` are the pluggable interfaces. Implement `Transport` to add a
backend; every backend is held to the same behaviour by the conformance suite, so the code above runs
unchanged over any of them.

## Layout

| crate                 | role                                                                |
| --------------------- | ------------------------------------------------------------------- |
| `bifrost`             | facade: the connection API (`Node`, `Transport`, `Session`, `Discovery`) |
| `bifrost-core`        | identity: `NodeId`, an ed25519 public key with a crypto-suite tag   |
| `bifrost-transport`   | the `Transport` / `Session` / `Discovery` traits and `Node`         |
| `bifrost-iroh`        | transport backend over iroh (QUIC with NAT hole-punching)           |
| `bifrost-mem`         | in-process transport backend for hermetic tests                     |
| `bifrost-quirk`       | transport backend over [quirk](https://github.com/theia-hq/quirk), a from-scratch QUIC |
| `bifrost-mdns`        | discovery over mDNS on the local network                            |
| `bifrost-conformance` | transport-agnostic test suite every backend must pass               |
| `bifrost-wire`        | one-shot blob transfer over a stream, BLAKE3-verified end to end    |

## Things to know

- bifrost establishes the connection and hands you a byte-stream. It says nothing about what those bytes
  mean; that is the caller's protocol.
- Verified blob transfer lives one layer up in `bifrost-wire`, a sibling crate, not in the facade.
- Transports are interchangeable: iroh, an in-process backend, and a from-scratch QUIC all pass the same
  conformance suite, so an app dialing a given identity runs unchanged across them.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
