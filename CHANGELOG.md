# Changelog

All notable changes to bifrost, newest first.

## v0.8.0

### Breaking
- **A key that is not a usable ed25519 identity is refused wherever it enters:** key text, a Noise
  handshake, an iroh or quirk connection, a sealed key file. A usable key is the canonical encoding of
  a prime-order point. A point off the curve, a non-canonical encoding, a small-order point, or a point
  with a torsion component is refused, and `KeyError` names which. `[1u8; 32]` has a torsion component
  and is refused; the key the seed `[7; 32]` binds prints as
  `ed015jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwa`.
- **`NodeId::new` is gone.** `NodeId::try_new(kind, bytes)` checks the bytes and returns
  `Result<NodeId, KeyError>`. `NodeId::from_ed25519_secret` stays infallible.
- **`NodeIdParseError` is `#[non_exhaustive]` and gains `Key`.** A `match` on it needs a wildcard arm.
- **`NoiseError` gains `PeerKey`:** the peer's handshake named a key that is not a usable identity.
  `NoiseError` is not `#[non_exhaustive]`, so a `match` on it without a wildcard arm no longer compiles.
- **`bifrost-quirk`'s `BindError` is an enum:** `Bind` (quirk could not bind its socket) and `Key`.

### New
- **`KeyError` names the check a key failed:** `NotOnCurve`, `NotCanonical`, `SmallOrder`, or
  `HasTorsion`. It is `#[non_exhaustive]`, and `bifrost`, `bifrost-core`, and `bifrost-transport`
  export it.
- **`keystore`'s `FormatError` gains `PublicKey`:** the key file's stored public key is not a usable
  identity.

## v0.7.0

### Breaking
- **Key text starts with `ed01`**, named for the ed25519 suite. The tag is read in any case.
  `[1u8; 32]` prints as `ed01aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq`. Node id text is
  ASCII: non-ASCII input is refused before decoding, and case is folded with ASCII rules only.
- **The device-identity derivation context is `bifrost device identity v1: {label}`.** Every key derived
  with `derive_ed25519_child_secret` / `NodeId::derive_ed25519` changes.
- **A key file starts with `KEYSTORE`.** Files written by earlier versions do not open.
- **mDNS uses the service `_bifrost._udp`.**
- **Requires Rust 1.91** (iroh 1.1+ needs it), checked in CI.

### Changed
- **A serving node no longer announces its key over mDNS.** Its instance name is a random nonce and a
  tag that only a holder of the node's key can match, renewed at every start and every fifteen minutes;
  the SRV host carries the same name. A browser tests only the keys it is subscribed to, holds at most
  four names per node, and drops a name the new browse does not hear after a rotation. Anyone who dials
  the port still learns the key from the handshake. A node that only dials announces nothing.
- **Requires iroh 1.1 or later.** iroh 1.0.3 sent the dialed node's key in cleartext TLS SNI.

## v0.6.1

### Changed
- **An iroh bind on n0 no longer asks the local DNS resolver for a peer.** That query named the node it
  was about to dial, usually in plaintext to whatever resolver the network hands out. Peers are still
  found through n0's pkarr server over HTTPS. The cost: where HTTPS to n0 is blocked but DNS is not,
  there is no longer a DNS fallback.

## v0.6.0

### Breaking
- **A `KeyFile` is named with its kind.** `KeyFile::device(path)` names a device's own key, plain or
  sealed as its owner chooses; `KeyFile::root(path)` names a root key. `From<PathBuf>` and
  `From<&Path>` are gone, so every caller says which kind of key it expects at a path. An existing
  device key file is unchanged on disk and loads through `KeyFile::device`.
- **`Secret::derive_child` is gone.** It had no caller. The derivation itself stays in
  `bifrost-core` (`derive_ed25519_child_secret`, `NodeId::derive_ed25519`).

### New
- **A root key is its own sealed file kind.** A sealed root key records kind 2 in its header, where a
  device key records kind 1, and the kind is authenticated with the rest of the header. A file is read
  only as the kind its `KeyFile` names: a sealed device key where a root key belongs, or the reverse,
  is refused as `FormatError::WrongKind`. A root key is never written plain: a plain write, adopt, or
  migration through `KeyFile::root` refuses as `Error::PlainRoot`. A plain 32-byte file carries no
  kind, so it still loads from either slot, and the caller decides whether to use it.

## v0.5.0

### Breaking
- **`Discovery::resolve` is gone;** a source implements `subscribe` (below).
- **`Session::close` is required** on every transport's session. It drops the session at once, and
  every stream it held ends; there is no default, because a no-op close would leave streams running
  after the node decided to cut them.
- **Transport constructors borrow the seed** (`&[u8; 32]`) instead of taking it by value, and the
  futures they return hold no borrow of it, so a caller binds through `Secret::with_bytes` and the seed
  is never copied out. Child seeds come back as `Zeroizing`.
- **`bifrost-wire` errors split a foreign stream from another build.** `Error::Foreign` means the bytes
  are not bifrost-wire; `Error::VersionMismatch` means a bifrost-wire peer speaking another grammar.

### New
- **The `keystore` crate: where a node's secret key lives.** One key file per node, either plain (the
  32-byte seed, readable only by its owner) or sealed under a passphrase (a 144-byte file: Argon2id
  derives the key, XChaCha20-Poly1305 encrypts the seed, and the whole header is authenticated, so a
  locked file can still say which node it belongs to). `KeyFile` loads, writes without ever
  overwriting, adopts an existing key, and migrates between plain and sealed by writing the new form
  beside the old, reading it back, and only then replacing it. Passphrases typed as text are normalised
  to NFC, so a file sealed on one system opens on another. A file larger than 4 KiB, or one demanding
  more than 256 MiB to unlock, is refused before any work is done. Secrets are wiped from memory on
  drop.
- **`Session::close`** on every transport: iroh closes the connection, Noise tears down its streams and
  pumps, quirk calls `Connection::close`, mem closes its pipes. The conformance suite checks that close
  ends every stream the session held.


### Changed
- **The wire magic is read as an identity and a version.** A peer on another build of the same
  protocol is told apart from a different protocol, so an error names a version skew instead of
  garbage.
- **Discovery is a subscription, and a dial no longer waits a fixed time for it.**
  `Discovery::subscribe(node)` replaces `resolve`. It returns a `HintStream` of `AddrUpdate`s: `Hints`
  (the node's current addresses), `Removed` (none any more), or `Settled` (the source has finished its
  first look and found nothing). `wait_ready` and the 1.5 s dial wait behind it are gone.

  `Node::connect` hands the feed to the transport, and the transport reads it as its bind allows. mem
  and the iroh n0 binds dial at once with whatever the feed already holds. A bind that can only reach
  a peer through its addresses (iroh local and offline, quirk) waits for the first answer, for as long
  as the caller's own deadline allows. A source implementing `Discovery` replaces `resolve` with
  `subscribe`, and the trait documents what a feed owes the dial reading it. `Transport` gains
  `connect_with_updates`, whose default reads the first answer and calls `connect`, so an existing
  transport compiles unchanged.

- **A cold dial on an iroh n0 bind no longer waits for mDNS.** On a LAN with no internet, a dial made
  before mDNS has heard the peer (typically in the first 1.5 s after the node starts) now fails where
  it used to wait and succeed. Dialing again once the peer has been heard succeeds. With internet,
  iroh finds the peer by its key as before, and the first bytes may go through the relay until a
  direct path is found.

- **A merged discovery feed fails the dial when every source has failed.** `Layered` still lets one
  source's failure pass while the other can serve the dial. When every source has stopped with no
  addresses and at least one of them failed, the dial now fails with that error instead of going ahead
  with no address and failing for a less useful reason.

- **A sealed dial that runs out of time before reaching the peer says so.** `NoiseError::DialTimeout`
  is new. The 10 s attempt deadline covers the discovery wait and the inner dial as well as the
  handshake, and running out before the inner dial returned is now a `DialTimeout`, not a
  `HandshakeTimeout`.

- **An mDNS feed ends when its `MdnsDiscovery` is dropped**, rather than staying pending on a service
  that can say no more.

## v0.4.0

A peer should not be able to name its own allocation.

### Fixed
- **A framed read sized its buffer to a number the peer chose.** `read_framed` took a `u32` off the
  wire and allocated that many bytes before reading one of them, so four `0xFF` bytes cost the host
  4 GiB on demand, and a receiver that then lossy-decoded the buffer peaked at three times that.
  Found by two independent reviews of every wire in the family at once.

  `MAX_HEADER_LEN` is 64 KiB and the number is derived rather than chosen: the header names one
  blob, so the largest legitimate one is a name, POSIX bounds a whole path at 4 KiB, and this leaves
  sixteen times that. It is also exactly the streaming chunk the receive path already holds, so the
  header can never be the largest allocation in a transfer.

  The bound is enforced at BOTH ends. An over-long header now fails on the sending side with the
  sender's own error instead of arriving as a remote rejection mid-frame, because whoever defines a
  wire owns both sides of it.

### Changed
- **`Error` is `#[non_exhaustive]` and gains `OversizedHeader`.** Same reasoning the refusal type
  took in v0.3.0: hardening a wire adds classes, and a consumer that carries an arm for a class it
  cannot name is a consumer that cannot silently inherit the wrong one. `Truncated` was the wrong
  answer for an oversized frame, which is not a truncated one: a peer whose stream simply ended
  deserves a different word from one that asked for 4 GiB.

## v0.3.0

Adding a refusal class should cost one release, not four.

### Changed
- **`Refusal` is `#[non_exhaustive]`.** It was a closed set in the crate that sits under every stream
  protocol in the family, so naming a new class of refusal was a breaking change that had to walk
  bifrost, tightbeam, services and swoosh in order before any of it could ship. That price was paid
  by the class never being added. It is now one release here and an arm downstream, added when each
  consumer is ready rather than all at once.

  The attribute moves the cost onto consumers, and the arm it forces is the dangerous one: a
  wildcard written to make the build pass is exactly the hole that let swoosh's `forward` dial as a
  stranger for months behind `_ => Ok(None)`. So the enum's own documentation says what that last
  arm owes a reader, with a worked example, and a `compile_fail` doctest holds the attribute itself
  because no runtime test can. Remove the attribute and that doctest fails as "compiled
  successfully, but it's marked compile_fail".

  Existing code that matches on the three variants needs one more arm. It should name the class it
  cannot read and refuse to stand in for another: substituting `NotAdmitted` invents an
  authorization ruling out of a message that carried none.

  No wire change. Three variants, three tag bytes, `MAGIC` untouched.

### Fixed
- **The `Refusal` enum doc no longer contradicts its own variant.** It still described `Unavailable`
  as "a post-admission host-resource failure", the narrow reading deliberately removed in 7feda79
  because a dialer who can recover the admission bit out of a refusal has been handed an oracle. The
  variant's own documentation twelve lines below had said so ever since. The enum-level text now
  agrees: the failure is the host's own and rules on nothing about the dialer.

## v0.2.3

An address we hand out is one that will still be there tomorrow.

### Fixed
- **A temporary IPv6 address is no longer published or handed over.** `HostAddrs` classified every
  address the OS reported, so on any host with IPv6 privacy addressing an RFC 8981 temporary address
  sat beside its stable twin, indistinguishable. Two consequences, and the larger one was on the wire:
  `Advertising::of_dialable` publishes everything scoped `Internet` or `Network`, so a node was
  MULTICASTING a rotating privacy address onto every network it joined. The other is that a consumer
  handed one to a human, and macOS deprecates it at about 24h and expires it at about 7d, so the peer's
  copy rots inside a day. `if-addrs` reports flags for an INTERFACE and never for an ADDRESS, so there
  was nothing to read; there is now, via netlink `RTM_GETADDR` on Linux and `SIOCGIFAFLAG_IN6` on the
  BSDs, with a documented no-op on every other target. The rule is one-directional: drop only what the
  kernel positively reports as temporary or deprecated, so a failed socket, a failed ioctl, a name that
  will not fit `IFNAMSIZ`, or a platform with no answer all KEEP the address, because dropping a real
  address on a syscall failure is worse than keeping a temporary one.
- **`is_globally_routable` delivers what its doc claims.** It admitted 6to4 `2002::/16`, Teredo
  `2001::/32`, AMT, ORCHID, RFC 9637 documentation space `3fff::/20`, and on the v4 side `198.18.0.0/15`
  (the range tap-mode Zscaler and WARP hand out), `240.0.0.0/4`, `192.0.0.0/24`, `192.88.99.0/24` and
  `0.0.0.0/8` beyond the exact unspecified address.

### Added
- **`Dialable` says WHY a set is short.** `Missing` is `Nothing`, `Interfaces`, `Flags` or `Expiring`,
  and the three causes are mutually exclusive by construction rather than by convention: the interface
  list is read before the flags, so losing it means never asking, and unread flags drop nothing, so a
  drop implies the flags were read. `Flags` is honest that the list is WHOLE and unchecked rather than
  short. A positive report is not a failure, which is why this exists: deprecation can take every SLAAC
  global at once on a prefix rotation or a wake from sleep, while those addresses still accept inbound,
  since RFC 4862 deprecation deprioritizes an address as a SOURCE and says nothing about it as a
  destination. `Expiring` carries the dropped addresses' scope CLASSES and never the addresses, which
  are the one thing privacy addressing exists to keep unpublished. A signal, not a floor: nothing keeps
  a deprecated address.
- **`ScopeClass` and `Scope::class`,** so a class can be asked about as a class. `Expiring::reached`
  took a `Scope`, which compared tunnels by link name, so a link whose only address expired left no
  surviving row to take the name from and the question could not be formed at all.

### Changed
- **`Reach` is `Scope` in this crate.** Reach is node-scale, and `bifrost_iroh::Reach` is the relay and
  resolver a NODE leans on; this is one address's scope. Two sibling crates spending one word on
  unrelated concepts made every consumer of both qualify forever.
- **A gap in a family this bind never expands is not this bind's gap.** The interface read hands its
  findings forward and only `Dialable::of_host` narrows them against the sockets actually bound, because
  the read holds only half of what names a missing set. A v4-only bind therefore reports neither a v6
  drop nor an unread-flags caveat, and a concrete bind reports nothing at all, by the rule rather than a
  special case: it answers at exactly the address it named, so no address this host stopped answering on
  was ever a row it could lose.
- **`unsafe_code = "deny"` on the workspace,** allowed back in the two platform reads only. These are
  the first `unsafe` blocks in bifrost and they arrived with no lint.

## v0.2.2

An unavailable refusal is about the host, not about the dialer.

### Changed
- **`Refusal::Unavailable` widens from "the peer admitted the dial but could not serve it" to "the host
  could not complete this dial for a reason of its own".** A dialer could read the old meaning as proof of
  having been admitted, and that narrowness left a pre-admission failure of the host's own with nowhere
  honest to go: a gate whose evaluation runs out of time decided nothing about the caller's authority, and
  telling them they were not admitted is a lie they act on. Doc only; no wire change and no signature
  change. A caller that matches the variant should treat it as transient and retry, and must never record
  it as an authorization outcome.

## v0.2.1

The addresses a bind answers on, and how far each of them reaches.

### New
- **`bifrost_mdns::Dialable`, `At` and `Reach`, and `Node::bound_sockets`.** The expansion that turns a
  bind into the concrete sockets it answers on was private to the mDNS publisher, so a consumer that
  needed the same answer for a different purpose had to read the publisher's own report about how far its
  advertisement reached, which is a different question. It is public now, and each socket carries how far
  it reaches: the internet, this network, one named point-to-point link, or this machine only. A private
  address and a unique-local one behave identically and look nothing alike, while a unique-local and a
  global IPv6 address look alike and do not, so the two routable classes are told apart rather than
  folded.

### Changed
- **The expansion no longer drops point-to-point links.** They are carried as their own reach class,
  named by the link. A wildcard bind demonstrably answers on a tunnel address, so dropping it was
  publication policy rather than a property of the address. What goes on the mDNS wire is unchanged: the
  publisher applies that policy itself, and its tests pass with their values untouched.

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
