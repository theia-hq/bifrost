//! quirk-backed implementation of the Bifrost transport interface.
//!
//! Maps quirk's endpoint, connection, and streams onto the [`Transport`] and [`Session`] traits, so
//! our from-scratch UDP transport is interchangeable with every other transport and held to the same
//! behaviour by the conformance suite. quirk dials by address, so this pairs with a discovery that
//! maps a [`NodeId`] to direct hints.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

pub use bifrost_core::NodeId;
use bifrost_core::{Addr, BoxError, ConnInfo, CryptoKind, Error, KeyError, Path};
pub use bifrost_transport::{Announced, Session, Transport};

/// A quirk-backed endpoint.
pub struct Endpoint {
    inner: quirk::Endpoint,
    /// This endpoint's own identity, parsed once at bind so `node_id` never re-reads quirk's key.
    node: NodeId,
}

impl Endpoint {
    /// Bind a quirk endpoint with a fresh identity.
    pub async fn bind() -> Result<Self, BindError> {
        Self::adopt(quirk::Endpoint::bind().await.map_err(BindError::Bind)?)
    }

    /// Bind with a persisted identity, from a raw 32-byte ed25519 secret, so the [`NodeId`] is stable
    /// across runs. Mirrors the iroh persisted-secret constructors (`bind_reachable_with_secret` for a
    /// serving bind, `bind_dialing_with_secret` for a dialing one): each derives the ed25519 verifying
    /// key from the same secret, so the same key yields the same [`NodeId`] over either transport. quirk
    /// has no address registry to publish to, so one constructor covers both roles here. That
    /// identical-identity-across-transports property is what the transport-swap demo rests on.
    ///
    /// Borrows the secret, and the bind it returns does not: `secret.with_bytes(bind_with_secret)`
    /// makes no copy of its own. quirk itself takes the secret by value, so the one copy made here is
    /// the one handed to it.
    pub fn bind_with_secret(
        secret: &[u8; 32],
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        let bind = quirk::Endpoint::bind_with_secret(*secret);
        async move { Self::adopt(bind.await.map_err(BindError::Bind)?) }
    }

    /// Wrap a bound quirk endpoint, parsing the key it announces as its own.
    fn adopt(inner: quirk::Endpoint) -> Result<Self, BindError> {
        let node = NodeId::try_new(CryptoKind::Ed25519, inner.public_key().to_bytes())
            .map_err(BindError::Key)?;
        Ok(Self { inner, node })
    }
}

impl Transport for Endpoint {
    type Security = Announced;
    type Session = QuirkSession;

    fn node_id(&self) -> NodeId {
        self.node
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

    /// The one UDP socket this endpoint owns, at the address it was bound to. quirk binds a single
    /// wildcard v4 socket, so this is the wildcard itself, not the loopback hint `local_addr` derives
    /// from it. A socket whose address cannot be read is reported as no socket rather than guessed.
    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner.local_addr().into_iter().collect()
    }

    async fn connect(&self, addr: Addr) -> Result<QuirkSession, Error> {
        let dialed = addr.node;
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

        // The peer announces its own key in the plaintext handshake. Bind the dialed-vs-reached
        // invariant that every layer above assumes: the identity we reached must be the one we dialed.
        // A plaintext MITM still defeats this (phase 1 Noise closes that); it closes the accidental
        // mismatch and makes the invariant explicit rather than silently trusting a self-announced key.
        let reached = NodeId::try_new(CryptoKind::Ed25519, conn.peer_key())
            .map_err(|err| Error::Connect(Box::new(err)))?;
        if reached != dialed {
            return Err(Error::Connect(Box::new(IdentityMismatch {
                dialed,
                reached,
            })));
        }
        Ok(QuirkSession {
            conn,
            peer: reached,
        })
    }

    async fn accept(&self) -> Result<QuirkSession, Error> {
        let conn = self
            .inner
            .accept()
            .await
            .map_err(|err| Error::Accept(Box::new(err)))?;
        let peer = NodeId::try_new(CryptoKind::Ed25519, conn.peer_key())
            .map_err(|err| Error::Accept(Box::new(err)))?;
        Ok(QuirkSession { conn, peer })
    }

    /// quirk drains per session, not per endpoint: each connection's send engine retransmits until its
    /// data and FIN are acked, and [`QuirkSession::wait_closed`] resolves only once that drain
    /// completes. The endpoint holds no separate buffered state to flush, so closing it is nothing
    /// beyond dropping it. A caller that needs delivery guaranteed awaits `wait_closed` on the session
    /// first, which is the wire's contract and what `bifrost-conformance::close_drains` enforces.
    async fn close(&self) {}
}

/// A quirk-backed session: one connection to a peer.
pub struct QuirkSession {
    conn: quirk::Connection,
    /// The key the peer announced, parsed once where the session is built: `peer` cannot refuse.
    peer: NodeId,
}

impl Session for QuirkSession {
    type Security = Announced;
    type Write = quirk::SendStream;
    type Read = quirk::RecvStream;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(quirk::SendStream, quirk::RecvStream), Error> {
        self.conn
            .open_bi()
            .map_err(|err| Error::Stream(Box::new(err)))
    }

    async fn accept_bi(&self) -> Result<(quirk::SendStream, quirk::RecvStream), Error> {
        // quirk carries one stream per connection today, so it is available exactly once. The bifrost
        // contract is "accept the NEXT stream": once the one stream is taken there is no next stream
        // until the connection ends, so block until it does rather than reporting `Closed` immediately.
        // Returning eagerly here would make a serve loop that races `accept_bi` against its in-flight
        // stream work (iroh, mem, where a second `accept_bi` pends) tear the session down mid-exchange.
        // This is the single-stream shape of "no more streams"; connection ids and multi-stream retire
        // it (quirk phase after Noise), at which point a real second stream can resolve this instead.
        // Honest limitation: a wedged peer that neither opens a new stream nor closes leaves this task
        // parked until the connection ends; the per-operation timeout on the future-work list bounds it.
        // Match `Closed` (the taken-stream case) explicitly so that once multi-stream lands, a genuine
        // stream error surfaces as `Stream` instead of being folded into a graceful close.
        match self.conn.accept_bi() {
            Ok(stream) => Ok(stream),
            Err(quirk::Error::Closed) => {
                self.conn.wait_closed().await;
                Err(Error::Closed)
            }
            Err(err) => Err(Error::Stream(Box::new(err))),
        }
    }

    async fn wait_closed(&self) {
        self.conn.wait_closed().await;
    }

    /// Stops the connection's engines, so its stream halves fail wherever they are held. The peer is
    /// NOT told: quirk's wire has no close frame yet, so it learns only by its own silence handling.
    /// That frame is quirk's to add, and the conformance suite records the gap by name.
    fn close(&self) {
        self.conn.close();
    }

    /// quirk is direct-only (no relay yet), so the path is always [`Path::Direct`] and the remote is
    /// the peer's socket address. It carries no rtt estimator of its own yet, so `rtt` stays `None`;
    /// a caller that wants an rtt over quirk measures one with an application-level round-trip probe. Reads
    /// Direct honestly today and gains Relayed once derpie lands.
    fn conn_info(&self) -> ConnInfo {
        ConnInfo {
            path: Path::Direct,
            rtt: None,
            remote: Some(self.conn.peer_addr()),
        }
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
pub enum BindError {
    /// quirk could not bind its socket.
    #[error("bind quirk endpoint")]
    Bind(#[source] quirk::Error),
    /// The endpoint's own key is not a usable identity.
    ///
    /// Does not occur for a key quirk derives from its own secret.
    #[error("endpoint key is not a usable identity")]
    Key(#[source] KeyError),
}

/// The peer reached did not present the identity that was dialed.
///
/// nauthy and every authorization layer above the transport rest on `session.peer()` being the peer
/// that was addressed. This guards the invariant at the boundary so a mismatch surfaces as a connect
/// error instead of a session that silently speaks for the wrong key.
#[derive(Debug, thiserror::Error)]
#[error("reached peer {reached} does not match dialed peer {dialed}")]
pub struct IdentityMismatch {
    dialed: NodeId,
    reached: NodeId,
}

#[cfg(test)]
mod tests {
    use bifrost_transport::SecurityProfile as _;

    use super::{Announced, Endpoint, Transport};

    /// The declared profile is PINNED per backend: every consumer's trust decision rests on it, so a
    /// silent promotion to a proof-bearing profile fails HERE, in the crate that declares it, rather than
    /// downstream in code that went on believing it. `Announced` is this crate's honest profile
    /// (self-announced identity, plaintext channel).
    #[test]
    fn the_declared_profile_is_pinned_to_announced() {
        assert_eq!(
            <Endpoint as Transport>::Security::SECURITY,
            Announced::SECURITY
        );
    }
}
