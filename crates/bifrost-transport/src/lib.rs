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
use std::collections::HashMap;

pub use bifrost_core::NodeId;
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
