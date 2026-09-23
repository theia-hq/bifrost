use bifrost::{Node, StaticDiscovery, Transport};
use bifrost_conformance::{
    PeerNotice, bound_sockets_are_bind_truth, close_drains, close_ends_held_streams,
    direct_conn_info, identity_binding, reach_roundtrip, wildcard_bind_is_not_rewritten,
    wrong_key_rejected,
};
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

/// iroh proves the peer from the TLS handshake, so both ends attribute the dialed identity.
#[tokio::test]
async fn iroh_identity_binding() {
    identity_binding(
        Endpoint::bind_local().await.expect("bind sender"),
        Endpoint::bind_local().await.expect("bind receiver"),
    )
    .await;
}

/// A dial to a key the receiver does not hold fails the raw-public-key handshake: no session, and no
/// way for a responder to speak for an identity it cannot prove.
#[tokio::test]
async fn iroh_wrong_key_rejected() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let fabricated = Endpoint::bind_local()
        .await
        .expect("bind fabricated")
        .node_id();
    let sender = Endpoint::bind_local().await.expect("bind sender");
    wrong_key_rejected(sender, receiver, fabricated).await;
}

/// iroh over loopback hole-punches straight to a direct path, so `conn_info` reports
/// [`bifrost::Path::Direct`] and names the remote. This exercises the real path-set reduction, not the
/// default: the mapping from iroh's live `PathList` down to a `ConnInfo` runs here end to end.
#[tokio::test]
async fn iroh_direct_conn_info() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    direct_conn_info(sender, receiver).await;
}

/// iroh's bind truth is iroh's own bound-socket set: the sockets the endpoint opened, reported as
/// bound, and matching the hints `local_addr` derives from them.
#[tokio::test]
async fn iroh_bound_sockets_are_bind_truth() {
    let endpoint = Endpoint::bind_local().await.expect("bind endpoint");
    bound_sockets_are_bind_truth(&endpoint);
}

/// `bind_local` binds the wildcard, so bind truth keeps `0.0.0.0` (and `[::]` where the host has a v6
/// socket) where `local_addr` would have rewritten it to loopback. This is the distinction a
/// publisher needs to expand a wildcard without expanding a deliberate loopback bind.
#[tokio::test]
async fn iroh_wildcard_bind_is_not_rewritten() {
    let endpoint = Endpoint::bind_local().await.expect("bind endpoint");
    wildcard_bind_is_not_rewritten(&endpoint);
}

/// Closing an iroh session closes the QUIC connection, so every stream on it fails on both ends, even
/// one a detached task still holds.
#[tokio::test]
async fn iroh_close_ends_held_streams() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    close_ends_held_streams(sender, receiver, PeerNotice::Told).await;
}
