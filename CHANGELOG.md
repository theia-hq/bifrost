# Changelog

All notable changes to bifrost, newest first.

## v0.2.0

Bind truth reaches discovery, so a node advertises addresses a peer can dial, and a bind can name a relay and a resolver of its own.

### Changed
- **A parsed relay or resolver URL is pointer-sized.** Both newtypes box their URL, so a consumer can
  hold one inside a command enum without inflating every sibling variant; a size test pins it.

### New
- **`bifrost-mdns` enumerates this host's addresses.** A wildcard bind (`0.0.0.0`, `[::]`) is expanded through `if-addrs` into the host's concrete non-loopback addresses on the bound port, so a node that bound every interface advertises addresses a peer can actually dial. A concrete address is published exactly as bound: a `127.0.0.1` bind stays loopback and is never expanded into a LAN reach it did not bind. Point-to-point links (utun, tun, wg, a tailnet) and link-local addresses are never published: neither has a LAN behind it, and a link-local address is unusable without a scope no record carries. The published set and the multicast egress pin come from that one set.
- **`Reach`: the relay and the resolver a bind uses.** `bifrost-iroh` gains `Endpoint::bind_reachable_with_secret_via` and `Endpoint::bind_dialing_with_secret_via`, taking a `Reach` whose relay and resolver halves are each n0's or one the caller runs (`RelayUrl` and `ResolverUrl`, `https` only); the existing binds are unchanged and are n0's on both halves.

### Changed
- **BREAKING: `Transport` requires `bound_sockets()`.** A new required trait method, no default: the sockets a transport actually bound, with an unspecified IP preserved and empty allowed. `local_addr()` rewrites a wildcard bind to loopback so the hint is dialable here, which makes a wildcard bind and a deliberate loopback bind the same value; a publisher must tell them apart. Every backend implements it (iroh reports iroh's own bound set, quirk its UDP socket, mem none, `Noise<T>` forwards the inner's), and the conformance suite now checks it against what a transport bound.
- **BREAKING: `MdnsDiscovery::advertise` reports what it advertised.** It takes the bind set and returns `Started { discovery, advertising }`, where `Advertising` names the outcome: `OnLan` (at least one non-loopback address published), `LoopbackOnly` (this machine only), or `BrowseOnly` (nothing publishable, with the cause). Having nothing to advertise no longer fails and is no longer `disabled()`: the node still browses and still resolves. The one remaining error is the service failing to start.

## v0.1.1

The serving bind publishes the node's address record; the dialing bind resolves without writing one.

### New
- **`Endpoint::bind_dialing_with_secret`.** The dialing bind: n0 resolution and relays, no address record, for a process that does not accept connections under the key.

### Changed
- **BREAKING: `bind_with_secret` is renamed `bind_reachable_with_secret`.** The name now states the write: it publishes this endpoint's address record, so only the process that accepts connections under the key calls it.

### Fixed
- **A dialing bind no longer overwrites a serving node's address record.** It registers the n0 resolvers with no pkarr publisher, so a short-lived dial under a key another process is serving cannot send peers to its own dead relay.

## v0.1.0

The first release: reach a peer by public key over iroh, an in-process backend, or a from-scratch QUIC,
with one conformance suite over the three and a sealed wrapper for a transport that only announces the
peer.

### New
- **The connection API.** `Node`, `Transport`, `Session`, and `Discovery` in the `bifrost` facade: dial a
  `NodeId` and get a bidirectional byte stream, with discovery resolving the peer's address instead of the
  caller naming a host and port.
- **Identity and the typed refusal.** `NodeId` (an ed25519 public key tagged with its crypto suite, built
  from raw key bytes with `NodeId::new` or `NodeId::from_ed25519_secret`), `CryptoKind`, `Addr`,
  `ConnInfo`, and the dialer-visible `Refusal` class (`NotAdmitted`, `BadRequest`, `Unavailable`, each
  detail bounded to 1 KiB), exported through the facade so a caller matches the class instead of parsing
  formatted text.
- **A declared security profile per backend.** Every transport names `Sealed` (iroh), `Announced` (quirk,
  phase 0), or `InProcess` (mem), with the `PeerProven`, `Confidential`, and `Secure` compile-time bounds,
  so a consumer can require proof of the peer and an announced transport is rejected at compile time.
- **`bifrost-noise`.** `Noise<T>` wraps an announced transport with a Noise XX handshake: the X25519
  static is signed by the ed25519 `NodeId`, the handshake payload carries `NodeId || sig` in msg2/msg3,
  the dial side pins the dialed key, and the wrapper declares `Sealed` for either wrappable inner.
- **The transport backends.** `bifrost-iroh` (QUIC with NAT hole-punching; `bind`, `bind_with_secret`,
  `bind_offline` for a direct-hint-only node, and `bind_local_with_secret` for a persisted identity with
  relays and the portmapper pinned off), `bifrost-mem` (in-process), and `bifrost-quirk` (the from-scratch
  QUIC transport).
- **`bifrost-mdns` and composable discovery.** LAN discovery over multicast DNS with a bounded peer cache,
  `Layered` to union a hint table with a learned resolver, and the `NoDiscovery` and `StaticDiscovery`
  sources.
- **Device identity derivation.** `NodeId::derive_ed25519(root, label)` and `derive_ed25519_child_secret`
  compute a device's address offline from the root secret and a label; the machine adopts the child secret
  and comes up as that identity.
- **`Session::conn_info()`.** A cheap, synchronous, best-effort readback of the session's current path
  (`Direct`, `Relayed`, `Mixed`, `Unknown`), rtt, and remote address, with the honest `Unknown` default.
- **`bifrost-wire`.** One-shot blob transfer over any byte stream, verified end to end against the BLAKE3
  root, re-exported as `bifrost::wire`.
- **The conformance suite.** `bifrost-conformance` runs reach, close/drain, identity-binding, and
  wrong-key cases over every backend, proven against a deliberately fabricating transport, and documents
  what it can and cannot prove.

### Fixed
- **A dial waits for discovery to answer.** The dial awaits `Discovery::wait_ready` when a resolve comes
  up empty, and only the dialed target's record or the bound ends the wait, so a self echo cannot release
  it; the v4-only browse drops the unroutable IPv6 leg.
- **The mDNS peer cache is bounded to 1024 peers.** An on-LAN flood of distinct fake `NodeId`s can no
  longer grow the map without bound.
- **A multi-port mDNS bind advertises honestly.** The first IPv4 socket picks the advertised port and only
  its addresses publish; a multi-port bind with no IPv4 socket errors by name instead of guessing.
- **A torn Noise session reads as a reset, never a clean EOF.** A full per-stream queue during teardown
  can no longer drop the reset chunk and present `Ok(())` to the reader; the cancelled-write stale-frame
  and drop-path reset losses are fixed in the same change.
- **A quirk session's second `accept_bi` pends until the connection ends.** The single-stream adapter
  returned `Closed` eagerly and tore a live session down mid-exchange (a live ping over quirk saw 100%
  loss); it now matches the iroh and mem contract, and a real error surfaces instead of a fabricated
  close.
- **A reached identity is asserted.** `bifrost-quirk::connect` refuses a session whose self-announced key
  does not equal the dialed `NodeId`, until the phase-1 Noise handshake makes identity cryptographic.
