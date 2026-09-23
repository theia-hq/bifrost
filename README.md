# bifrost

Open a byte-stream to a machine identified by its public key, wherever it is on the internet, across
NATs, without knowing its address. Identity is an ed25519 public key (a `NodeId`): you address *who* a
peer is, not *where*. bifrost gives you the connection and nothing more; what you send over it is up to
you.

It carries the connection over its own backends: iroh (QUIC with NAT hole-punching), an in-process
backend for tests, and [quirk](https://github.com/theia-hq/quirk), a QUIC-shaped transport written
from scratch over UDP. `bifrost-noise` seals a backend that carries plaintext: a Noise handshake over
one of its streams, proving the peer's key and carrying logical streams inside it.

**The name.** Bifröst is the burning rainbow bridge of Norse myth, the span that reaches from one
world to any other. This crate is the bridge to a peer: name a public key and it carries a
connection there.

> Experimental. The APIs change without notice; not ready for production use.

## Add it as a dependency

Not published to crates.io. Point at the repo:

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
backend; the conformance suite holds every backend to the same byte-movement behaviour, and each
declares a `Security` profile (`Sealed`, `Announced`, or `InProcess`) a consumer can require as a bound.

Backends are not interchangeable past that. The interface is bidirectional byte-streams and nothing
else, and how many a session gives you is the backend's own: iroh and the in-process backend open
another on demand, while bare quirk carries one per session, so a second `open_bi` returns an error.
Wrapping quirk in `bifrost-noise` lifts that, up to 64 at a time inside the one.

## If you already use iroh

`bifrost-iroh` is a narrowing of iroh, not an improvement on it. The interface above it is dial-by-key
and bidirectional streams, and an address is a `NodeId` plus socket-address hints, so anything iroh
offers outside that shape does not come through. If iroh's own API is what you want, use iroh. Two
things live above this seam that iroh alone does not give you.

**A backend with no network in it.** `bifrost-mem` moves the same bytes over in-process channels and
passes the same byte-movement suite as iroh, binding no socket.
[tightbeam](https://github.com/theia-hq/tightbeam) and [swoosh](https://github.com/theia-hq/swoosh)
run their product surfaces on it, so their tests exercise real sessions and real streams with no
network under them. This is the seam's main proven value today.

**Noise over a transport that carries plaintext.** `bifrost-noise` wraps a transport carrying
plaintext on one stream: it runs `Noise_XX_25519_ChaChaPoly_SHA256` over that stream, proves the peer
holds the key for the `NodeId` it was dialed under, and carries framed logical streams inside it.
Without it, quirk is only fit for traffic you would publish. It is exercised over quirk on loopback
UDP and against a hostile in-process peer, where a fabricated signer, a replayed handshake, and a
spliced third flight each yield no session.

## The crates

| crate                 | role                                                                |
| --------------------- | ------------------------------------------------------------------- |
| `bifrost`             | facade: the connection API (`Node`, `Transport`, `Session`, `Discovery`) |
| `bifrost-core`        | identity: `NodeId`, an ed25519 public key with a crypto-suite tag   |
| `bifrost-transport`   | the `Transport` and `Session` traits                                |
| `bifrost-iroh`        | transport backend over iroh (QUIC with NAT hole-punching)           |
| `bifrost-mem`         | in-process transport backend for hermetic tests                     |
| `bifrost-noise`       | Noise over a plaintext transport: proves the peer's key, seals the session, many streams inside one |
| `bifrost-quirk`       | transport backend over [quirk](https://github.com/theia-hq/quirk), a QUIC-shaped transport written from scratch |
| `bifrost-mdns`        | discovery over mDNS on the local network                            |
| `bifrost-conformance` | transport-agnostic test suite every backend must pass               |
| `bifrost-wire`        | one-shot blob transfer over a stream, BLAKE3-verified end to end    |

This page describes the default branch.

## Things to know

- bifrost establishes the connection and hands you a byte-stream. It says nothing about what those bytes
  mean; that is the caller's protocol.
- Verified blob transfer lives in `bifrost-wire`, a sibling crate the facade re-exports as `bifrost::wire`.
- Passing the conformance suite is not a security claim. Each transport declares its own `Security`
  profile (`Sealed`, `Announced`, or `InProcess`), and a consumer states the bound it needs:
  `PeerProven` to trust the peer's key, `Secure` to carry a secret. A transport that does not meet the
  bound does not compile in.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
