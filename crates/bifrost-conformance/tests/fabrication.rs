//! A fabricating transport fails the identity cases.
//!
//! These tests pin the assertions that catch a transport which lies about identity: one reports a
//! peer other than the dialed key, the other hands back a session for any key it is handed. Both must
//! panic, so a transport whose `peer()` has no basis cannot go green through the suite.

use bifrost::{Addr, Announced, CryptoKind, Error, NodeId, Session, Transport};
use bifrost_conformance::{identity_binding, wrong_key_rejected};
use tokio::io;

/// The identity the fabricated transport claims for itself.
fn claimed() -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [0x01; NodeId::KEY_LEN])
}

/// The identity the fabricated session attributes to the peer, which is never the key dialed.
fn attributed() -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [0x02; NodeId::KEY_LEN])
}

/// A transport that answers every dial with a session for a key nobody reached.
struct Fabricator;

impl Transport for Fabricator {
    type Security = Announced;
    type Session = FabricatedSession;

    fn node_id(&self) -> NodeId {
        claimed()
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(claimed())
    }

    async fn connect(&self, _addr: Addr) -> Result<FabricatedSession, Error> {
        Ok(FabricatedSession)
    }

    async fn accept(&self) -> Result<FabricatedSession, Error> {
        Ok(FabricatedSession)
    }

    async fn close(&self) {}
}

/// A session that reports an identity no handshake established.
struct FabricatedSession;

impl Session for FabricatedSession {
    type Security = Announced;
    type Write = io::Sink;
    type Read = io::Empty;

    fn peer(&self) -> NodeId {
        attributed()
    }

    async fn open_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn accept_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn wait_closed(&self) {}
}

/// A session that speaks for a key the dialer never asked for fails [`identity_binding`].
#[tokio::test]
#[should_panic(expected = "the dialer attributes the key it dialed")]
async fn fabricated_peer_fails_identity_binding() {
    identity_binding(Fabricator, Fabricator).await;
}

/// A transport that accepts every key fails [`wrong_key_rejected`], the case a naive announced-key
/// wrapper passes today.
#[tokio::test]
#[should_panic(expected = "identity that was never reached")]
async fn session_for_wrong_key_fails_wrong_key_rejection() {
    let fabricated = NodeId::new(CryptoKind::Ed25519, [0x03; NodeId::KEY_LEN]);
    wrong_key_rejected(Fabricator, Fabricator, fabricated).await;
}
