//! iroh-backed implementation of the Bifrost transport interface.
//!
//! iroh does the hard parts (QUIC, NAT traversal, relay fallback, raw-public-key TLS) so a session
//! to a [`NodeId`] works across the internet. This crate maps iroh's endpoint, connection, and
//! streams onto the [`Transport`] and [`Session`] traits, and keeps iroh's own address type from
//! leaking past this boundary.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use bifrost_core::CryptoKind;
pub use bifrost_core::NodeId;
use bifrost_transport::{Addr, Error};
pub use bifrost_transport::{Session, Transport};
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{EndpointAddr, EndpointId, PublicKey, SecretKey};

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

    async fn finish(
        builder: iroh::endpoint::Builder,
        secret: SecretKey,
    ) -> Result<Self, BindError> {
        let inner = builder
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(BindError)?;
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
#[error("bind iroh endpoint")]
pub struct BindError(#[source] iroh::endpoint::BindError);
