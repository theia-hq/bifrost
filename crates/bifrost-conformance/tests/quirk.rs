use bifrost::{Node, NodeId, StaticDiscovery, Transport};
use bifrost_conformance::{
    PeerNotice, bound_sockets_are_bind_truth, close_drains, close_ends_held_streams,
    direct_conn_info, identity_binding, reach_roundtrip, wildcard_bind_is_not_rewritten,
    wrong_key_rejected,
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

/// quirk passes the same round-trip as iroh and mem. The proof that quirk satisfies the
/// transport interface.
#[tokio::test]
async fn quirk_reach_roundtrip() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    reach_roundtrip(sender, receiver).await;
}

/// quirk honors the close/drain contract: a sender that writes, finishes, and closes still
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
    let fabricated = NodeId::from_ed25519_secret(&[0x11; NodeId::KEY_LEN]);
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

/// This backend's bind truth is its one UDP socket, at the address it was bound to, matching the hint
/// `local_addr` derives from it.
#[tokio::test]
async fn quirk_bound_sockets_are_bind_truth() {
    let endpoint = Endpoint::bind().await.expect("bind endpoint");
    bound_sockets_are_bind_truth(&endpoint);
}

/// quirk binds `0.0.0.0:0`, so bind truth keeps the wildcard where `local_addr` would have rewritten
/// it to loopback: a publisher can tell this bind from one a caller pinned to `127.0.0.1`.
#[tokio::test]
async fn quirk_wildcard_bind_is_not_rewritten() {
    let endpoint = Endpoint::bind().await.expect("bind endpoint");
    wildcard_bind_is_not_rewritten(&endpoint);
}

/// Closing a quirk session ends every stream it holds locally, with an error. The peer is not told:
/// the wire has no close frame yet, so the peer-side checks are an owned gap rather than a pass.
#[tokio::test]
async fn quirk_close_ends_held_streams() {
    let receiver = Endpoint::bind().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    close_ends_held_streams(
        sender,
        receiver,
        PeerNotice::NotYet(
            "the wire has no close frame, so the peer learns only by its own silence handling; \
             owner: the backend's repo, whose roadmap carries the close frame; trigger: Session::close \
             landing",
        ),
    )
    .await;
}
