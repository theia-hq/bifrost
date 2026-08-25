use bifrost::{Node, StaticDiscovery, Transport};
use bifrost_conformance::reach_roundtrip;
use bifrost_quirk::Endpoint;

/// Our own QUIC passes the same round-trip as iroh and mem: dialing by NodeId via a StaticDiscovery
/// that resolves the target to its local address, hermetically over loopback. The proof that quirk
/// satisfies the transport seam.
#[tokio::test]
async fn quirk_reach_roundtrip() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let sender_transport = Endpoint::bind().await.expect("bind sender");

    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    let sender = Node::new(sender_transport, discovery);

    reach_roundtrip(sender, receiver).await;
}
