use bifrost::{NoDiscovery, Node};
use bifrost_conformance::{close_drains, reach_roundtrip};
use bifrost_mem::MemTransport;

/// The in-process transport passes the same blob round-trip as iroh. A channels-only transport and a
/// QUIC transport passing the identical check is the proof the interface is transport-agnostic. mem
/// self-discovers via its registry, so it composes with NoDiscovery.
#[tokio::test]
async fn mem_reach_roundtrip() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    reach_roundtrip(sender, receiver).await;
}

/// The in-process transport honors the close/drain contract: a sender that writes, finishes, and
/// closes still delivers every byte to a clean stream end.
#[tokio::test]
async fn mem_close_drains() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    close_drains(sender, receiver).await;
}
