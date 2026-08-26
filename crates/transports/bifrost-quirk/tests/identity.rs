//! The dialed-vs-reached identity guard.
//!
//! quirk's plaintext handshake carries a self-announced key. Every layer above the transport (nauthy's
//! authorization in particular) trusts `session.peer()` to be the peer that was addressed, so
//! `connect` must reject a session whose reached key is not the dialed key. This is the interim guard
//! until phase 1 Noise makes the identity cryptographically real.

use bifrost_core::CryptoKind;
use bifrost_quirk::{Endpoint, NodeId};
use bifrost_transport::{Addr, Error, Transport};

/// Dialing a real quirk endpoint at its real address but under the wrong NodeId is rejected with a
/// connect error, rather than yielding a session that speaks for an identity that was never reached.
#[tokio::test]
async fn connect_rejects_a_mismatched_identity() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let hints = receiver.local_addr().hints;

    // A fabricated identity that is not the receiver's. Dial it at the receiver's real address.
    let wrong = NodeId::new(CryptoKind::Ed25519, [0x11; NodeId::KEY_LEN]);
    assert_ne!(wrong, receiver.node_id(), "the fabricated key must differ");

    let dialer = Endpoint::bind().await.expect("bind dialer");
    let result = dialer.connect(Addr { node: wrong, hints }).await;

    match result {
        Err(Error::Connect(_)) => {}
        Err(other) => panic!("expected a connect error, got {other:?}"),
        Ok(_) => panic!("connect yielded a session for an identity that was never reached"),
    }
}

/// Dialing the receiver under its own NodeId at its own address succeeds: the guard rejects only a
/// genuine mismatch, never a correct dial.
#[tokio::test]
async fn connect_accepts_the_dialed_identity() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let addr = Addr {
        node: receiver.node_id(),
        hints: receiver.local_addr().hints,
    };

    let dialer = Endpoint::bind().await.expect("bind dialer");
    let (_session, _accepted) = tokio::join!(
        async { dialer.connect(addr).await.expect("connect") },
        async { receiver.accept().await.expect("accept") }
    );
}

/// The same 32-byte secret yields the same NodeId over quirk and over iroh. This is the property the
/// transport-swap demo rests on: one persisted key, one address, whichever transport is bound under it.
/// Both adapters derive the identity as the ed25519 verifying key of the secret tagged `Ed25519`, so a
/// node that serves over iroh and a node that serves over quirk from the same key are the same peer.
#[tokio::test]
async fn bind_with_secret_matches_the_iroh_node_id() {
    let secret = [0x5a; 32];

    let quirk = Endpoint::bind_with_secret(secret)
        .await
        .expect("bind quirk");
    let iroh = bifrost_iroh::Endpoint::bind_with_secret(secret)
        .await
        .expect("bind iroh");

    assert_eq!(
        quirk.node_id(),
        iroh.node_id(),
        "the same secret must yield the same NodeId across transports"
    );
}
