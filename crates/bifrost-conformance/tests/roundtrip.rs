use bifrost::{Node, StaticDiscovery, Transport};
use bifrost_conformance::reach_roundtrip;
use bifrost_iroh::Endpoint;

/// The iroh transport passes the blob round-trip, hermetically over loopback, dialing by NodeId via a
/// StaticDiscovery that resolves the target to its local addresses. Proves discovery + transport + wire.
#[tokio::test]
async fn iroh_reach_roundtrip() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender_transport = Endpoint::bind_local().await.expect("bind sender");

    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    let sender = Node::new(sender_transport, discovery);

    reach_roundtrip(sender, receiver).await;
}
