//! quirk-backed implementation of the Bifrost transport seam.
//!
//! Maps quirk's endpoint, connection, and streams onto the [`Transport`] and [`Session`] traits, so
//! our own from-scratch QUIC is interchangeable with every other transport and held to the same
//! behaviour by the conformance suite. quirk dials by address, so this pairs with a discovery that
//! resolves a [`NodeId`] to direct hints.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bifrost_core::CryptoKind;
pub use bifrost_core::NodeId;
use bifrost_transport::{Addr, BoxError, Error};
pub use bifrost_transport::{Session, Transport};

/// A quirk-backed endpoint.
pub struct Endpoint {
    inner: quirk::Endpoint,
}

impl Endpoint {
    /// Bind a quirk endpoint with a fresh identity.
    pub async fn bind() -> Result<Self, BindError> {
        Ok(Self {
            inner: quirk::Endpoint::bind().await.map_err(BindError)?,
        })
    }
}

impl Transport for Endpoint {
    type Session = QuirkSession;

    fn node_id(&self) -> NodeId {
        NodeId::new(CryptoKind::Ed25519, self.inner.public_key().to_bytes())
    }

    fn local_addr(&self) -> Addr {
        let hints = self
            .inner
            .local_addr()
            .map(loopback_for_unspecified)
            .into_iter()
            .collect();
        Addr {
            node: self.node_id(),
            hints,
        }
    }

    async fn connect(&self, addr: Addr) -> Result<QuirkSession, Error> {
        let peer = addr
            .hints
            .into_iter()
            .next()
            .ok_or_else(|| Error::Connect(missing_hint()))?;
        let conn = self
            .inner
            .connect(peer)
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        Ok(QuirkSession { conn })
    }

    async fn accept(&self) -> Result<QuirkSession, Error> {
        let conn = self
            .inner
            .accept()
            .await
            .map_err(|err| Error::Accept(Box::new(err)))?;
        Ok(QuirkSession { conn })
    }

    async fn close(&self) {}
}

/// A quirk-backed session: one connection to a peer.
pub struct QuirkSession {
    conn: quirk::Connection,
}

impl Session for QuirkSession {
    type Write = quirk::SendStream;
    type Read = quirk::RecvStream;

    fn peer(&self) -> NodeId {
        NodeId::new(CryptoKind::Ed25519, self.conn.peer_key())
    }

    async fn open_bi(&self) -> Result<(quirk::SendStream, quirk::RecvStream), Error> {
        self.conn
            .open_bi()
            .map_err(|err| Error::Stream(Box::new(err)))
    }

    async fn accept_bi(&self) -> Result<(quirk::SendStream, quirk::RecvStream), Error> {
        self.conn
            .accept_bi()
            .map_err(|err| Error::Stream(Box::new(err)))
    }

    async fn wait_closed(&self) {
        self.conn.wait_closed().await;
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

fn missing_hint() -> BoxError {
    Box::new(std::io::Error::other("quirk needs a direct address hint"))
}

/// Binding the quirk endpoint failed.
#[derive(Debug, thiserror::Error)]
#[error("bind quirk endpoint")]
pub struct BindError(#[source] quirk::Error);
