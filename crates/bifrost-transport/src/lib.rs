//! The Bifrost transport interface.
//!
//! A [`Transport`] establishes authenticated, encrypted [`Session`]s to a peer identified by its
//! [`NodeId`]. This is the pluggable boundary: iroh today, a raw-QUIC transport next, others later,
//! all interchangeable and all held to the same behaviour by the conformance suite. Everything
//! above this boundary (the wire, the products) is transport-blind.
//!
//! Streams are exposed as associated types bounded by [`AsyncRead`]/[`AsyncWrite`], so the boundary is a
//! plain byte-stream interface with no boxing: a transport differs only in how a session is
//! established, never in how bytes flow once it is.

use core::net::SocketAddr;
use core::time::Duration;
use std::collections::HashMap;

pub use bifrost_core::{NodeId, NodeIdParseError};
use tokio::io;

/// How to reach a peer: its identity, plus optional direct-address hints.
///
/// A bare identity (no hints) is dialed via discovery. Hints let a caller reach a peer directly,
/// bypassing discovery, which is how local and hermetic connections work. This replaces any
/// transport-specific ticket: the rest of Bifrost speaks only [`NodeId`] and hints.
#[derive(Debug, Clone)]
pub struct Addr {
    /// The peer's identity.
    pub node: NodeId,
    /// Direct address hints, tried alongside or instead of discovery.
    pub hints: Vec<SocketAddr>,
}

impl Addr {
    /// An address carrying only an identity, to be resolved by discovery.
    pub fn from_node(node: NodeId) -> Self {
        Self {
            node,
            hints: Vec::new(),
        }
    }
}

impl From<NodeId> for Addr {
    fn from(node: NodeId) -> Self {
        Self::from_node(node)
    }
}

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

/// How a session's bytes reach the peer: peer to peer, bounced off a relay, or both.
///
/// This answers the single most reassuring question a p2p tool can: "am I actually direct, or bouncing
/// off a relay?" A transport that tracks NAT traversal (iroh) reports it honestly, and it can change
/// over a session's life: a connection often starts [`Relayed`](Self::Relayed) and upgrades to
/// [`Direct`](Self::Direct) as hole-punching completes, so a reader should treat it as the CURRENT
/// path, not a fixed property. A transport that cannot tell reports [`Unknown`](Self::Unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Path {
    /// Peer to peer: bytes flow straight to the remote address, no relay in the middle.
    Direct,
    /// Bounced off a relay: no direct path is (yet) established.
    Relayed,
    /// Both a direct and a relayed path are open at once (an upgrade in progress, or multipath).
    Mixed,
    /// The transport does not expose its path (in-process, or not yet instrumented).
    #[default]
    Unknown,
}

/// A best-effort snapshot of how a session reaches its peer, for diagnostics like `swoosh status`.
///
/// Best-effort by design: every field a transport cannot determine is absent (the [`Path`] is
/// [`Unknown`](Path::Unknown), the rest are `None`), so this never fabricates a reassuring answer it
/// cannot back. It is a cheap, synchronous accessor snapshotting current state, deliberately OFF the
/// async hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnInfo {
    /// Whether the current path is direct, relayed, mixed, or unknown.
    pub path: Path,
    /// The transport's current round-trip estimate, if it tracks one.
    pub rtt: Option<Duration>,
    /// The remote address the current path reaches, if the transport exposes it.
    pub remote: Option<SocketAddr>,
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

/// A transport-neutral error, preserving the underlying cause by source.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Dialing a peer failed.
    #[error("connect to peer")]
    Connect(#[source] BoxError),
    /// Accepting an inbound session failed.
    #[error("accept session")]
    Accept(#[source] BoxError),
    /// Opening or accepting a stream failed.
    #[error("stream")]
    Stream(#[source] BoxError),
    /// The transport has shut down.
    #[error("transport closed")]
    Closed,
}

/// A boxed underlying error, kept as the source of an [`Error`].
pub type BoxError = Box<dyn core::error::Error + Send + Sync + 'static>;

/// Resolves a [`NodeId`] to reachable address hints.
///
/// Orthogonal to [`Transport`]: discovery PRODUCES hints, a transport CONSUMES them via [`Addr`].
/// A self-discovering transport (iroh, mem) pairs with [`NoDiscovery`]; a transport with no built-in
/// discovery (raw QUIC) pairs with a real resolver ([`StaticDiscovery`], later mDNS, pkarr).
#[allow(async_fn_in_trait)]
pub trait Discovery {
    /// Resolve an identity to address hints. An empty result means "no hints, let the transport try".
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error>;
}

/// Discovery for transports that resolve internally (iroh, mem): yields no external hints.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDiscovery;

impl Discovery for NoDiscovery {
    async fn resolve(&self, _node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        Ok(Vec::new())
    }
}

/// Discovery from a fixed in-memory table. The reference resolver for tests and static deployments.
#[derive(Debug, Clone, Default)]
pub struct StaticDiscovery {
    table: HashMap<NodeId, Vec<SocketAddr>>,
}

impl StaticDiscovery {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the direct addresses for an identity.
    pub fn insert(&mut self, node: NodeId, addrs: Vec<SocketAddr>) {
        self.table.insert(node, addrs);
    }
}

impl Discovery for StaticDiscovery {
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        Ok(self.table.get(&node).cloned().unwrap_or_default())
    }
}

/// A composed endpoint: a [`Transport`] paired with a [`Discovery`].
///
/// This is what applications hold. It makes discovery an explicit part of composition: you dial a
/// bare [`NodeId`], the discovery resolves hints, and the transport establishes the session. The app
/// never touches a concrete transport type beyond constructing this once.
pub struct Node<T, D> {
    transport: T,
    discovery: D,
}

impl<T: Transport, D: Discovery> Node<T, D> {
    /// Compose a transport with a discovery mechanism.
    pub fn new(transport: T, discovery: D) -> Self {
        Self {
            transport,
            discovery,
        }
    }

    /// This endpoint's identity.
    pub fn node_id(&self) -> NodeId {
        self.transport.node_id()
    }

    /// A directly-dialable address for this endpoint.
    pub fn local_addr(&self) -> Addr {
        self.transport.local_addr()
    }

    /// Dial a peer by identity: resolve hints via discovery, then establish a session.
    pub async fn connect(&self, node: NodeId) -> Result<T::Session, Error> {
        let hints = self.discovery.resolve(node).await?;
        self.transport.connect(Addr { node, hints }).await
    }

    /// Accept the next inbound session.
    pub async fn accept(&self) -> Result<T::Session, Error> {
        self.transport.accept().await
    }

    /// Gracefully close, draining buffered data first.
    pub async fn close(&self) {
        self.transport.close().await;
    }
}
