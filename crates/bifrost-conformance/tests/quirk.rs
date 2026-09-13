use bifrost::{CryptoKind, Node, NodeId, StaticDiscovery, Transport};
use bifrost_conformance::{
    close_drains, direct_conn_info, identity_binding, reach_roundtrip, wrong_key_rejected,
};
use bifrost_quirk::Endpoint;

/// Compose a quirk sender that dials `receiver` by NodeId via a StaticDiscovery resolving it to its
/// local address, hermetically over loopback.
// A test helper, not a `#[test]` fn, so `allow-expect-in-tests` does not reach the expect inside it.
#[allow(clippy::expect_used)]
async fn dialing(receiver: &Endpoint) -> Node<Endpoint, StaticDiscovery> {
    let sender_transport = Endpoint::bind().await.expect("bind sender");
    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    Node::new(sender_transport, discovery)
}

/// Our own QUIC passes the same round-trip as iroh and mem. The proof that quirk satisfies the
/// transport interface.
#[tokio::test]
async fn quirk_reach_roundtrip() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    reach_roundtrip(sender, receiver).await;
}

/// Our own QUIC honors the close/drain contract: a sender that writes, finishes, and closes still
/// delivers every byte, and the receiver reads a clean end. This is the case that a no-op close or an
/// unreliable FIN would fail, which loopback's lossless echo never exposes.
#[tokio::test]
async fn quirk_close_drains() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    close_drains(sender, receiver).await;
}

/// quirk announces its key in a plaintext handshake, so both ends must attribute the key that was
/// dialed. Phase 1 Noise replaces the announcement with a proof; this assertion does not change.
#[tokio::test]
async fn quirk_identity_binding() {
    identity_binding(
        Endpoint::bind().await.expect("bind sender"),
        Endpoint::bind().await.expect("bind receiver"),
    )
    .await;
}

/// A fabricated key dialed at the receiver's real address is rejected by the dialed-vs-reached guard,
/// so a plaintext responder cannot hand up a session for a key it does not hold.
#[tokio::test]
async fn quirk_wrong_key_rejected() {
    let fabricated = NodeId::new(CryptoKind::Ed25519, [0x11; NodeId::KEY_LEN]);
    wrong_key_rejected(
        Endpoint::bind().await.expect("bind sender"),
        Endpoint::bind().await.expect("bind receiver"),
        fabricated,
    )
    .await;
}

/// quirk is direct-only, so a session reports [`bifrost::Path::Direct`] and names the peer's address.
#[tokio::test]
async fn quirk_direct_conn_info() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    direct_conn_info(sender, receiver).await;
}
