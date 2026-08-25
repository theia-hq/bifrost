# bifrost

Pubkey-addressed overlay networking. Identity is an ed25519 public key: you dial a peer by *who* they
are, not *where* they are, over any transport, across NAT. `bifrost` is the **reach** seam — open an
authenticated, bidirectional byte-stream to a `NodeId` and stay agnostic to whatever crosses it.

> Experimental. APIs will change and it is not ready for production use.

## Usage

Compose a transport with a discovery mechanism into a `Node`, then dial peers by identity:

```rust
use bifrost::{Node, NoDiscovery, Session};

let node = Node::new(transport, NoDiscovery);
let session = node.connect(peer_id).await?;
let (mut writer, mut reader) = session.open_bi().await?;
```

`Transport`, `Session`, and `Discovery` are the pluggable seams. Implement `Transport` to add a
backend; every implementation is held to one behaviour by the conformance suite.

## Layout

| crate                 | role                                                          |
| --------------------- | ------------------------------------------------------------ |
| `bifrost`             | facade — the reach API (`Node`, `Transport`, `Session`, `Discovery`) |
| `bifrost-core`        | identity (`NodeId`, crypto-versioned)                        |
| `bifrost-transport`   | the transport seam + `Node` / `Discovery`                    |
| `bifrost-iroh`        | transport backend over iroh (QUIC + hole-punching)           |
| `bifrost-mem`         | in-process transport backend (tests)                         |
| `bifrost-conformance` | transport-agnostic reach test suite                          |
| `bifrost-wire`        | verified one-shot blob transfer over a stream                |

## Things to know

- bifrost is **reach only**: it establishes sessions and hands you byte-streams. It says nothing about
  what those bytes mean.
- Verified blob transfer lives one layer up in `bifrost-wire`, a sibling crate, not in the facade.
- Transports are interchangeable. iroh and an in-process transport ship in-tree; others (our own QUIC)
  live out-of-tree and still pass the same conformance suite.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
