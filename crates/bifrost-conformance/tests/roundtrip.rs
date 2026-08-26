use bifrost::{Node, StaticDiscovery, Transport};
use bifrost_conformance::{close_drains, reach_roundtrip};
use bifrost_iroh::Endpoint;

/// Compose an iroh sender that dials `receiver` by NodeId via a StaticDiscovery resolving it to its
/// local addresses, hermetically over loopback.
// A test helper, not a `#[test]` fn, so `allow-expect-in-tests` does not reach the expect inside it.
#[allow(clippy::expect_used)]
async fn dialing(receiver: &Endpoint) -> Node<Endpoint, StaticDiscovery> {
    let sender_transport = Endpoint::bind_local().await.expect("bind sender");
    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    Node::new(sender_transport, discovery)
}

/// The iroh transport passes the blob round-trip. Proves discovery + transport + wire.
#[tokio::test]
async fn iroh_reach_roundtrip() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    reach_roundtrip(sender, receiver).await;
}

/// The iroh transport honors the close/drain contract: a sender that writes, finishes, and closes
/// still delivers every byte to a clean stream end. iroh's real close is the reference behaviour here.
#[tokio::test]
async fn iroh_close_drains() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    close_drains(sender, receiver).await;
}
