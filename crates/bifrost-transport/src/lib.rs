//! The Bifrost transport interface.
//!
//! A [`Transport`] moves bytes to a peer identified by its [`NodeId`].
//!
//! This is the pluggable boundary: iroh, and an in-process backend for tests that has no handshake
//! and proves nothing about a peer. Both expose the same byte-stream interface and pass the same
//! conformance suite.
//! Everything above this boundary (the wire, the products) is transport-blind.
//!
//! This crate is the byte-moving interface and nothing else: implement [`Transport`] + [`Session`] to
//! add a transport. The transport-neutral vocabulary it speaks ([`Addr`], [`Error`], [`ConnInfo`],
//! [`Path`], [`PathChanges`], and the [`Discovery`](bifrost_core::Discovery) contract) lives in
//! `bifrost-core`.
//!
//! Streams are exposed as associated types bounded by [`AsyncRead`]/[`AsyncWrite`], so the boundary
//! is a plain byte-stream interface with no boxing: a transport differs only in how a session is
//! established, never in how bytes flow once it is.
//!
//! # Admitting a new transport
//!
//! A new backend runs parity tests and carries nothing else until it clears this list.
//!
//! 1. Prove the peer: a named handshake binds the `NodeId` private key (TLS with raw public keys, a
//!    Noise pattern). Pairing, a uid, or a transport-level channel is not `NodeId` proof.
//! 2. Prove key possession in that handshake and test it: the accepted peer holds the dialed key's
//!    private half, and a claim that cannot sign for it yields no session.
//! 3. Protect every stream with authenticated encryption under keys from that same handshake, so
//!    the bytes come from the peer it proved and no one on the path reads or alters them. A signed
//!    handshake followed by plaintext does not clear this step.
//! 4. Pass the shared conformance suite in the backend's own CI, against a pinned conformance rev.
//! 5. Run the identity falsifiers where the wire is drivable: a wrong-key dial is refused, and a
//!    hostile dialer claiming a foreign `NodeId` is never attributed it. A stack whose handshake
//!    lives inside a dependency (iroh's RPK TLS) cannot be driven from the suite; state that and
//!    keep the review of that stack.
//! 6. Bound the handshake and the wire: a handshake deadline, per-peer and global session and stream
//!    caps, bounded queues and buffers, and bounded parsing (closing on abuse, never growing).
//! 7. Fuzz or property-test every byte parser the transport owns.
//! 8. Pin and deny-check every crypto dependency; hand-rolled primitives are refused.
//! 9. Run a live adversarial pass with observed evidence: wrong key, on-path impersonation, replay,
//!    and any planned downgrade.
//!
//! Until all of that passes: no credential, no gated route, no default reach path, and no
//! peer-supplied transport selection. A backend that has not cleared this list is not wired into
//! any binary.

use core::net::SocketAddr;

pub use bifrost_core::{
    Addr, AddrUpdate, ConnInfo, Error, HintStream, KeyError, NodeId, NodeIdParseError, Path,
    PathChanges, Relay,
};
use tokio::io;

// `async fn` in these traits is deliberate. The returned futures are not `Send`-bounded, which is
// fine here: callers drive sessions with structured concurrency (join/select on one task), not
// `tokio::spawn` across threads. If a future consumer must spawn sessions onto other threads,
// revisit with `trait_variant` or an explicit `-> impl Future + Send`. See DECISIONS.
/// A pluggable transport: binds a local identity and moves [`Session`]s to and from peers.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// The session type this transport establishes.
    type Session: Session;

    /// This transport's local identity.
    fn node_id(&self) -> NodeId;

    /// A directly-dialable address for this transport (identity plus local hints).
    fn local_addr(&self) -> Addr;

    /// The sockets this transport is bound to, exactly as bound.
    ///
    /// Raw bind truth: an unspecified IP (`0.0.0.0`, `[::]`) is reported as bound, never rewritten,
    /// and a transport that owns no socket reports none. Empty is a fact, not an error.
    ///
    /// This is NOT [`local_addr`](Self::local_addr), whose hints rewrite an unspecified bind to
    /// loopback so the address is dialable on this host. That rewrite is many-to-one: it maps a
    /// wildcard bind and a deliberate loopback bind onto the same value, and a publisher must tell
    /// them apart, because it has to expand the first into the host's real addresses and must never
    /// expand the second. Required with no default: the only default a transport-blind trait could
    /// offer is the rewritten hint set, which would compile that confusion into every backend that
    /// stayed silent.
    fn bound_sockets(&self) -> Vec<SocketAddr>;

    /// Dial a peer: the floor, a one-shot dial with whatever hints the caller holds.
    ///
    /// A transport may remember the addresses it is given for a peer, for as long as it keeps state
    /// for that peer, and try them in later dials to the same peer. The identity check still decides
    /// who is reached; an address only chooses where the dial goes.
    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error>;

    /// Dial a peer whose hints a discovery feed supplies. Additive: a caller holding only an
    /// [`Addr`] keeps calling [`connect`](Self::connect), and nothing about that path changes.
    ///
    /// The default consumes the feed for the FIRST observation, then dials once: `Hints` dials with
    /// them, `Removed` or the end of the feed dials the bare `addr`, and an `Err` fails the dial. It
    /// never waits beyond that first observation and never adds a timer, so the caller's deadline is
    /// the only bound; and the feed is dropped before the dial starts, so no later item can reach
    /// this attempt or start another one.
    ///
    /// Whether to wait at all is a fact about how the transport was bound, so it lives here and not
    /// in the caller. A transport that finds peers by itself overrides this to dial now; one that
    /// can use updates during an attempt overrides it to keep consuming. A wrapper that implements
    /// only [`connect`](Self::connect) inherits this default and silently shadows any such override
    /// in its inner transport, so a wrapper forwards this method to its inner one.
    async fn connect_with_updates(
        &self,
        addr: Addr,
        updates: HintStream,
    ) -> Result<Self::Session, Error> {
        self.connect(addr.seeded(updates.first().await)?).await
    }

    /// Accept the next inbound session.
    async fn accept(&self) -> Result<Self::Session, Error>;

    /// Gracefully close, draining buffered data so in-flight bytes are delivered first.
    async fn close(&self);
}

/// A session with a peer.
#[allow(async_fn_in_trait)]
pub trait Session {
    /// The writable half of a stream to the peer.
    type Write: io::AsyncWrite + Unpin + Send;
    /// The readable half of a stream from the peer.
    type Read: io::AsyncRead + Unpin + Send;

    /// The peer's identity: a key the handshake proved the peer holds the private half of, never one
    /// it only claimed. The in-process mem transport has no handshake; its peer is the other endpoint
    /// in the same process.
    fn peer(&self) -> NodeId;

    /// Open a bidirectional stream to the peer.
    ///
    /// The peer grants room for the streams this side opens. Against a peer on the same transport, a
    /// session carries at least 224 bidirectional streams at once. A stream counts until both ends have
    /// finished with it: each has closed its writer and read the other's to its end, or dropped both
    /// halves.
    ///
    /// Past the peer's room this waits and never errors for being full. A waiting open completes once
    /// fewer than 224 streams count, and may complete sooner. A peer that grants no room keeps it waiting
    /// indefinitely, so a caller that needs a bound sets its own deadline.
    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error>;

    /// Accept the next bidirectional stream from the peer.
    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error>;

    /// Wait until the peer closes the session, keeping it alive so final bytes are delivered.
    async fn wait_closed(&self);

    /// End the session now, ABRUPTLY, and every stream on it, whoever holds that stream.
    ///
    /// Dropping a session is not always the end of it: a transport whose streams keep their connection
    /// alive leaves it open while any stream is held, and a stream handed to a detached task can be held
    /// for as long as that task lives. A caller that must END a session, not merely stop serving it,
    /// calls this. The contract every transport meets, and the conformance suite checks:
    ///
    /// - **Abrupt.** Bytes not yet acknowledged are discarded. For a clean end, finish every stream and
    ///   await [`wait_closed`](Self::wait_closed) instead; this is the opposite operation.
    /// - **Every stream ends.** A held stream's reads and writes then fail with an error, never a clean
    ///   end, so a transfer the close cut short can never pass for a complete one.
    /// - **The peer learns of it.** Its reads on the session's streams error, and its
    ///   [`wait_closed`](Self::wait_closed) resolves.
    /// - **Afterwards,** [`open_bi`](Self::open_bi) and [`accept_bi`](Self::accept_bi) fail, and the
    ///   local [`wait_closed`](Self::wait_closed) resolves.
    /// - **Idempotent,** never blocks, and never panics.
    ///
    /// Required, with no default: a no-op default would be false for every transport whose streams
    /// outlive the session value, and a wrapper would inherit it silently.
    fn close(&self);

    /// A best-effort snapshot of how this session reaches the peer (direct vs relayed, rtt, remote).
    ///
    /// Additive and optional: the default returns [`Path::Unknown`] with no rtt or remote, so a
    /// transport that cannot tell (or has not been instrumented) compiles and behaves unchanged. A
    /// transport that tracks the path overrides this. A cheap synchronous accessor, not part of the
    /// byte-moving hot path.
    fn conn_info(&self) -> ConnInfo {
        ConnInfo::default()
    }

    /// The path carrying this session's bytes: the one in force now, then each change. The live
    /// counterpart of [`conn_info`](Self::conn_info); [`PathChanges`] states the rules.
    ///
    /// A transport whose path never moves, or that cannot tell, returns [`PathChanges::fixed`]. A
    /// session that wraps another returns the inner session's.
    fn path_changes(&self) -> PathChanges;
}
