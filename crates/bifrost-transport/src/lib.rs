//! The Bifrost transport interface.
//!
//! A [`Transport`] establishes authenticated, encrypted [`Session`]s to a peer identified by its
//! [`NodeId`]. This is the pluggable boundary: iroh today, a raw-QUIC transport next, others later,
//! all interchangeable and all held to the same behaviour by the conformance suite. Everything
//! above this boundary (the wire, the products) is transport-blind.
//!
//! This crate is the byte-moving seam and nothing else: implement [`Transport`] + [`Session`] to add
//! a transport. The transport-neutral vocabulary it speaks ([`Addr`], [`Error`], [`ConnInfo`],
//! [`Path`], and the [`Discovery`](bifrost_core::Discovery) contract) lives in `bifrost-core`.
//!
//! Streams are exposed as associated types bounded by [`AsyncRead`]/[`AsyncWrite`], so the boundary is a
//! plain byte-stream interface with no boxing: a transport differs only in how a session is
//! established, never in how bytes flow once it is.

pub use bifrost_core::{Addr, ConnInfo, Error, NodeId, NodeIdParseError, Path};
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

    /// Dial a peer.
    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error>;

    /// Accept the next inbound session.
    async fn accept(&self) -> Result<Self::Session, Error>;

    /// Gracefully close, draining buffered data so in-flight bytes are delivered first.
    async fn close(&self);
}

/// An authenticated, encrypted session with a peer.
#[allow(async_fn_in_trait)]
pub trait Session {
    /// The writable half of a stream to the peer.
    type Write: io::AsyncWrite + Unpin + Send;
    /// The readable half of a stream from the peer.
    type Read: io::AsyncRead + Unpin + Send;

    /// The peer's identity, as proven by the handshake.
    fn peer(&self) -> NodeId;

    /// Open a bidirectional stream to the peer.
    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error>;

    /// Accept the next bidirectional stream from the peer.
    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error>;

    /// Wait until the peer closes the session, keeping it alive so final bytes are delivered.
    async fn wait_closed(&self);

    /// A best-effort snapshot of how this session reaches the peer (direct vs relayed, rtt, remote).
    ///
    /// Additive and optional: the default returns [`Path::Unknown`] with no rtt or remote, so a
    /// transport that cannot tell (or has not been instrumented) compiles and behaves unchanged. A
    /// transport that tracks the path overrides this. A cheap synchronous accessor, not part of the
    /// byte-moving hot path.
    fn conn_info(&self) -> ConnInfo {
        ConnInfo::default()
    }
}
