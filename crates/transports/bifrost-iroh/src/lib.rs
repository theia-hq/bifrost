//! iroh-backed implementation of the Bifrost transport interface.
//!
//! iroh does the hard parts (QUIC, NAT traversal, relay fallback, raw-public-key TLS) so a session
//! to a [`NodeId`] works across the internet. This crate maps iroh's endpoint, connection, and
//! streams onto the [`Transport`] and [`Session`] traits, and keeps iroh's own address type from
//! leaking past this boundary.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub use bifrost_core::NodeId;
use bifrost_core::{Addr, ConnInfo, CryptoKind, Error, HintStream, Path};
pub use bifrost_transport::{Sealed, Session, Transport};
use iroh::endpoint::{
    Connection, PathList, PortmapperConfig, RecvStream, RelayMode, SendStream, presets,
};
use iroh::{EndpointAddr, EndpointId, PublicKey, SecretKey, TransportAddr};

mod reach;

pub use reach::{Reach, ReachUrlError, RelayHome, RelayUrl, Resolver, ResolverUrl};

/// The ALPN that identifies the Bifrost substrate protocol during the handshake.
pub const ALPN: &[u8] = b"bifrost/0";

/// A bound iroh endpoint.
pub struct Endpoint {
    inner: iroh::Endpoint,
    /// How this bind finds a peer, which decides whether a dial waits on a discovery feed.
    finding: Finding,
}

/// How an endpoint finds a peer, fixed by the bind that made it.
///
/// A bind fact rather than a transport fact: the same iroh endpoint type finds peers by key under
/// an n0-shaped bind and only by hints under a minimal or offline one, so no single answer could be
/// declared for the type.
#[derive(Debug, Clone, Copy)]
enum Finding {
    /// The bind registered an address lookup (pkarr, DNS) and relays, so iroh finds a peer by its
    /// key on its own. A dial never waits on a feed; it takes only what the feed already holds at
    /// that instant (a hint the caller supplied, a LAN record already heard).
    ByKey,
    /// A minimal or offline bind with no lookup of its own: a peer is reachable only through hints,
    /// so a dial waits for the feed's first answer.
    ByHints,
}

impl Finding {
    /// The address a dial under this bind goes with: the one read of the feed the bind allows.
    ///
    /// Kept apart from the dial so the choice is testable without a network: only the dial after it
    /// touches iroh. Both arms read the feed once and drop it, since iroh at this version takes no
    /// addresses into an attempt already running.
    async fn seed(self, addr: Addr, updates: HintStream) -> Result<Addr, Error> {
        match self {
            // Found by key: what the feed holds at this instant (a caller's hint, a LAN record
            // already heard), and never a wait for more, since iroh can find the peer without it.
            Self::ByKey => addr.seeded(updates.ready()),
            // Found only by hints: a dial with none has nothing to go to, so it waits for the
            // feed's first answer, bounded by whoever awaits the dial.
            Self::ByHints => addr.seeded(updates.first().await),
        }
    }
}

impl Endpoint {
    /// Bind with a fresh identity, using n0 discovery and relays so it is reachable by [`NodeId`]
    /// across NATs. The fresh-identity reachable shape: it publishes a record under a key generated per
    /// call that no dialer holds, like [`bind_reachable_with_secret`](Self::bind_reachable_with_secret).
    pub async fn bind() -> Result<Self, BindError> {
        Self::finish(
            Reach::default().serving(),
            SecretKey::generate(),
            Finding::ByKey,
        )
        .await
    }

    /// Bind with a persisted identity as a SERVING node: n0 discovery and relays, and publish this
    /// endpoint's address record (n0 pkarr/DNS) so peers reach it by key. The serving bind: bind this
    /// only from the process that accepts connections under the key.
    ///
    /// Every persisted-identity bind here borrows the secret and turns it into the endpoint's key
    /// before it returns; the future it returns holds that key, not the borrow. So a caller holding
    /// the secret in a wiping owner binds with `secret.with_bytes(Endpoint::bind_..)` and makes no
    /// copy of it.
    pub fn bind_reachable_with_secret(
        secret: &[u8; 32],
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::bind_reachable_with_secret_via(secret, Reach::default())
    }

    /// Bind with a persisted identity for DIALING ONLY: n0 resolution and relays, no address record.
    /// A dialer is not reachable at its key; publishing here overwrites whatever process IS serving
    /// that key (the 0.9.0 F1 finding: a short-lived command wrote its own relay, exited, and dialers
    /// followed a dead relay path). What n0 registers, minus its `PkarrPublisher`.
    pub fn bind_dialing_with_secret(
        secret: &[u8; 32],
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::bind_dialing_with_secret_via(secret, Reach::default())
    }

    /// Bind as a SERVING node over a caller-named [`Reach`]: the same publish-my-record bind as
    /// [`bind_reachable_with_secret`](Self::bind_reachable_with_secret), with the relay and the
    /// resolver each either n0's or one the caller runs.
    pub fn bind_reachable_with_secret_via(
        secret: &[u8; 32],
        reach: Reach,
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::finish(
            reach.serving(),
            SecretKey::from_bytes(secret),
            Finding::ByKey,
        )
    }

    /// Bind for DIALING ONLY over a caller-named [`Reach`]: the same no-record bind as
    /// [`bind_dialing_with_secret`](Self::bind_dialing_with_secret), with the relay and the resolver
    /// each either n0's or one the caller runs. A dialer must resolve through the same resolver as
    /// the node it is looking for, or that node's record is not there to find.
    pub fn bind_dialing_with_secret_via(
        secret: &[u8; 32],
        reach: Reach,
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::finish(
            reach.dialing(),
            SecretKey::from_bytes(secret),
            Finding::ByKey,
        )
    }

    /// Bind a local-only endpoint with a FRESH identity, for same-process tests (the conformance
    /// suite): no discovery, no relays, no fixed address. A node that must keep one address across
    /// runs binds [`bind_local_with_secret`](Self::bind_local_with_secret) instead.
    pub async fn bind_local() -> Result<Self, BindError> {
        Self::finish(
            iroh::Endpoint::builder(presets::Minimal),
            SecretKey::generate(),
            Finding::ByHints,
        )
        .await
    }

    /// Bind a local-only endpoint with a PERSISTED identity: no n0 discovery, no relays, no
    /// portmapper, on an OS-assigned port. Reachable only by direct address hints or the local
    /// discovery composed above, and the same key yields the same [`NodeId`] across runs.
    pub fn bind_local_with_secret(
        secret: &[u8; 32],
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::finish(
            iroh::Endpoint::builder(presets::Minimal)
                // `presets::Minimal` leaves both of these at the iroh defaults (relays on, portmapper
                // enabled). Pin them off explicitly so "no NAT traversal" is configuration, not an
                // accident of an empty relay map or a future preset change.
                .relay_mode(RelayMode::Disabled)
                .portmapper_config(PortmapperConfig::Disabled),
            SecretKey::from_bytes(secret),
            Finding::ByHints,
        )
    }

    /// Bind an OFFLINE endpoint: a persisted identity, no n0 discovery and no relays, at a fixed local
    /// address. Reachable ONLY via direct address hints, so two nodes on a LAN or a Docker
    /// network connect directly with nothing crossing the internet. The fixed port is what makes the
    /// address hardcodable: a peer names `host:port` and reaches it, no discovery service in the loop.
    pub fn bind_offline(
        secret: &[u8; 32],
        bind_addr: SocketAddr,
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        let secret = SecretKey::from_bytes(secret);
        async move {
            Self::finish(
                iroh::Endpoint::builder(presets::Minimal).bind_addr(bind_addr)?,
                secret,
                Finding::ByHints,
            )
            .await
        }
    }

    async fn finish(
        builder: iroh::endpoint::Builder,
        secret: SecretKey,
        finding: Finding,
    ) -> Result<Self, BindError> {
        let inner = builder
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        Ok(Self { inner, finding })
    }
}

impl Transport for Endpoint {
    type Security = Sealed;
    type Session = IrohSession;

    fn node_id(&self) -> NodeId {
        from_endpoint_id(self.inner.id())
    }

    fn local_addr(&self) -> Addr {
        let hints = self
            .inner
            .bound_sockets()
            .into_iter()
            .map(loopback_for_unspecified)
            .collect();
        Addr {
            node: self.node_id(),
            hints,
        }
    }

    /// iroh's own bound-socket set, unrewritten: the endpoint binds a v4 socket and, where the host
    /// has one, a v6 socket, each reported at the address it was actually bound to.
    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    async fn connect(&self, addr: Addr) -> Result<IrohSession, Error> {
        let endpoint_addr = to_endpoint_addr(addr).map_err(|err| Error::Connect(Box::new(err)))?;
        let conn = self
            .inner
            .connect(endpoint_addr, ALPN)
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        Ok(IrohSession { conn })
    }

    /// The feed is read as the bind allows ([`Finding::seed`]): a bind that finds peers by key
    /// never waits on it, and a hints-only bind waits for its first answer.
    async fn connect_with_updates(
        &self,
        addr: Addr,
        updates: HintStream,
    ) -> Result<IrohSession, Error> {
        self.connect(self.finding.seed(addr, updates).await?).await
    }

    async fn accept(&self) -> Result<IrohSession, Error> {
        let incoming = self.inner.accept().await.ok_or(Error::Closed)?;
        let conn = incoming.await.map_err(|err| Error::Accept(Box::new(err)))?;
        Ok(IrohSession { conn })
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

/// An iroh session: a single authenticated, encrypted connection.
pub struct IrohSession {
    conn: Connection,
}

impl Session for IrohSession {
    type Security = Sealed;
    type Write = SendStream;
    type Read = RecvStream;

    fn peer(&self) -> NodeId {
        from_endpoint_id(self.conn.remote_id())
    }

    async fn open_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        self.conn
            .open_bi()
            .await
            .map_err(|err| Error::Stream(Box::new(err)))
    }

    async fn accept_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        self.conn
            .accept_bi()
            .await
            .map_err(|err| Error::Stream(Box::new(err)))
    }

    async fn wait_closed(&self) {
        self.conn.closed().await;
    }

    /// A QUIC connection stays open while any of its streams is held, so dropping the session alone can
    /// leave it carrying streams a detached task still owns. Closing it ends every one of them at once.
    fn close(&self) {
        self.conn.close(0u32.into(), b"closed");
    }

    /// Map iroh's live path set onto a best-effort [`ConnInfo`]. iroh tracks every open path and marks
    /// one as selected for transmission; hole-punching means a session can start [`Path::Relayed`] and
    /// upgrade to [`Path::Direct`] as a direct path opens, so this reports the CURRENT state honestly.
    /// The rtt and remote come from the selected path (the one actually carrying bytes).
    fn conn_info(&self) -> ConnInfo {
        conn_info(&self.conn.paths())
    }
}

/// Reduce iroh's open-path snapshot to a [`ConnInfo`]. The [`Path`] classifies the set: all-direct is
/// [`Path::Direct`], all-relay is [`Path::Relayed`], a mix of both is [`Path::Mixed`], and no open path
/// yet is [`Path::Unknown`]. The rtt and remote describe the selected path (falling back to the first
/// open one), since that is the path bytes actually take.
fn conn_info(paths: &PathList<'_>) -> ConnInfo {
    let mut direct = false;
    let mut relayed = false;
    for path in paths {
        direct |= path.is_ip();
        relayed |= path.is_relay();
    }
    let path = match (direct, relayed) {
        (true, false) => Path::Direct,
        (false, true) => Path::Relayed,
        (true, true) => Path::Mixed,
        (false, false) => Path::Unknown,
    };

    let selected = paths.iter().find(|path| path.is_selected());
    let carrying = selected.or_else(|| paths.iter().next());
    ConnInfo {
        path,
        rtt: carrying.as_ref().map(|path| path.rtt()),
        remote: carrying.and_then(|path| direct_addr(path.remote_addr())),
    }
}

/// The direct socket address of a path, if it is an IP path. A relay path (or any future non-IP path
/// variant of iroh's `non_exhaustive` address) has no direct socket address to report, so it yields
/// `None` and [`ConnInfo::remote`] stays absent.
fn direct_addr(addr: &TransportAddr) -> Option<SocketAddr> {
    match addr {
        TransportAddr::Ip(socket) => Some(*socket),
        _ => None,
    }
}

/// Rewrite an unspecified bind address (`0.0.0.0` / `[::]`) to loopback so it is directly dialable
/// locally and never handed out as a wildcard hint.
fn loopback_for_unspecified(socket: SocketAddr) -> SocketAddr {
    match socket.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socket.port())
        }
        IpAddr::V6(v6) if v6.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), socket.port())
        }
        _ => socket,
    }
}

fn from_endpoint_id(id: EndpointId) -> NodeId {
    NodeId::new(CryptoKind::Ed25519, *id.as_bytes())
}

fn to_endpoint_addr(addr: Addr) -> Result<EndpointAddr, iroh::KeyParsingError> {
    let id = PublicKey::from_bytes(addr.node.key())?;
    let mut endpoint_addr = EndpointAddr::new(id);
    for hint in addr.hints {
        endpoint_addr = endpoint_addr.with_ip_addr(hint);
    }
    Ok(endpoint_addr)
}

/// Binding the local endpoint failed.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// The underlying iroh endpoint failed to bind (port in use, socket error).
    #[error("bind iroh endpoint")]
    Bind(#[from] iroh::endpoint::BindError),
    /// The requested fixed bind address was not a valid socket address.
    #[error("invalid bind address")]
    Addr(#[from] iroh::endpoint::InvalidSocketAddr),
}

#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod reach_tests;
