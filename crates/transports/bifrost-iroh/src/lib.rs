//! iroh-backed implementation of the Bifrost transport interface.
//!
//! iroh does the hard parts (QUIC, NAT traversal, relay fallback, raw-public-key TLS) so a session
//! to a [`NodeId`] works across the internet. This crate maps iroh's endpoint, connection, and
//! streams onto the [`Transport`] and [`Session`] traits, and keeps iroh's own address type from
//! leaking past this boundary.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

pub use bifrost_core::NodeId;
use bifrost_core::{Addr, ConnInfo, CryptoKind, Error, Path};
pub use bifrost_transport::{Session, Transport};
use iroh::endpoint::{Connection, PathList, RecvStream, SendStream, presets};
use iroh::{EndpointAddr, EndpointId, PublicKey, SecretKey, TransportAddr};

/// The ALPN that identifies the Bifrost substrate protocol during the handshake.
pub const ALPN: &[u8] = b"bifrost/0";

/// A bound iroh endpoint.
pub struct Endpoint {
    inner: iroh::Endpoint,
}

impl Endpoint {
    /// Bind with a fresh identity, using n0 discovery and relays so it is reachable by [`NodeId`]
    /// across NATs.
    pub async fn bind() -> Result<Self, BindError> {
        Self::finish(iroh::Endpoint::builder(presets::N0), SecretKey::generate()).await
    }

    /// Bind with a persisted identity, from a raw 32-byte ed25519 secret key, so the [`NodeId`] is
    /// stable across runs. Uses n0 discovery and relays like [`bind`](Self::bind).
    pub async fn bind_with_secret(secret: [u8; 32]) -> Result<Self, BindError> {
        Self::finish(
            iroh::Endpoint::builder(presets::N0),
            SecretKey::from_bytes(&secret),
        )
        .await
    }

    /// Bind a local-only endpoint (no discovery, no relays) for same-host and LAN use.
    pub async fn bind_local() -> Result<Self, BindError> {
        Self::finish(
            iroh::Endpoint::builder(presets::Minimal),
            SecretKey::generate(),
        )
        .await
    }

    /// Bind an OFFLINE endpoint: a persisted identity, no n0 discovery and no relays, at a fixed local
    /// address. Reachable ONLY via direct address hints (a `--peer`), so two nodes on a LAN or a Docker
    /// network connect directly with nothing crossing the internet. The fixed port is what makes the
    /// address hardcodable: a peer names `host:port` and reaches it, no discovery service in the loop.
    pub async fn bind_offline(secret: [u8; 32], bind_addr: SocketAddr) -> Result<Self, BindError> {
        Self::finish(
            iroh::Endpoint::builder(presets::Minimal).bind_addr(bind_addr)?,
            SecretKey::from_bytes(&secret),
        )
        .await
    }

    async fn finish(
        builder: iroh::endpoint::Builder,
        secret: SecretKey,
    ) -> Result<Self, BindError> {
        let inner = builder
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        Ok(Self { inner })
    }
}

impl Transport for Endpoint {
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

    async fn connect(&self, addr: Addr) -> Result<IrohSession, Error> {
        let endpoint_addr = to_endpoint_addr(addr).map_err(|err| Error::Connect(Box::new(err)))?;
        let conn = self
            .inner
            .connect(endpoint_addr, ALPN)
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        Ok(IrohSession { conn })
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

/// Rewrite an unspecified bind address (`0.0.0.0`) to loopback so it is directly dialable locally.
fn loopback_for_unspecified(socket: SocketAddr) -> SocketAddr {
    match socket.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socket.port())
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
