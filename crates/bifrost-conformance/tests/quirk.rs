use bifrost::{Node, StaticDiscovery, Transport};
use bifrost_conformance::{close_drains, reach_roundtrip};
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
