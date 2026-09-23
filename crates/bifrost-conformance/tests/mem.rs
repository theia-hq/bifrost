use bifrost::{NoDiscovery, Node, Transport};
use bifrost_conformance::{
    PeerNotice, close_drains, close_ends_held_streams, identity_binding, reach_roundtrip,
    unknown_conn_info, wrong_key_rejected,
};
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

/// The in-process transport attributes the dialed identity on both ends: the registry is keyed by
/// [`bifrost::NodeId`], so the key dialed is the key reached, exact by construction.
#[tokio::test]
async fn mem_identity_binding() {
    identity_binding(MemTransport::bind(), MemTransport::bind()).await;
}

/// A dial to an identity that is not bound in this process yields no session. The fabricated key is
/// minted and dropped, so the registry has no entry for it.
#[tokio::test]
async fn mem_wrong_key_rejected() {
    let receiver = MemTransport::bind();
    let sender = MemTransport::bind();
    let fabricated = MemTransport::bind().node_id();
    wrong_key_rejected(sender, receiver, fabricated).await;
}

/// The in-process transport is not path-instrumented, so it inherits the [`bifrost::Path::Unknown`]
/// default: `conn_info` is honest that an in-process session has no direct-vs-relay answer to give.
#[tokio::test]
async fn mem_unknown_conn_info() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    unknown_conn_info(sender, receiver).await;
}

/// The in-process transport binds no socket, so its bind truth is empty: there is nothing to publish
/// on a network, and empty is the honest answer rather than a fabricated loopback address.
#[test]
fn mem_binds_no_sockets() {
    let transport = MemTransport::bind();
    assert!(
        transport.bound_sockets().is_empty(),
        "an in-process transport binds no socket"
    );
}

/// Closing an in-process session ends every stream either side holds, with an error, and the peer
/// learns at once: the pair shares one close signal.
#[tokio::test]
async fn mem_close_ends_held_streams() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    close_ends_held_streams(sender, receiver, PeerNotice::Told).await;
}
