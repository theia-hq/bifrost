use bifrost::{Node, StaticDiscovery, Transport};
use bifrost_conformance::{
    Delivery, StreamEnd, StreamLimit, a_close_after_a_pending_delivery_errors_the_peer,
    a_delivered_stream_survives_a_close, a_dropped_writer_still_ends_cleanly,
    a_session_carries_its_stream_floor, abort_is_idempotent_and_writes_after_it_fail,
    abort_leaves_the_sessions_other_streams_alive, abort_leaves_the_streams_read_half_open,
    an_abort_after_shutdown_leaves_the_clean_end, an_aborted_writer_errors_the_peers_read,
    bound_sockets_are_bind_truth, close_drains, close_ends_held_streams,
    delivered_after_a_close_fails, delivered_after_an_abort_fails,
    delivered_finishes_an_open_stream, delivered_to_a_stopped_reader_fails, direct_conn_info,
    identity_binding, reach_roundtrip, wildcard_bind_is_not_rewritten, wrong_key_rejected,
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
    close_ends_held_streams(sender, receiver).await;
}

/// One iroh session carries the stream floor, and an open past the peer's room waits rather than
/// failing, then completes once fewer than the floor count: here each side finishes its writer and
/// reads the other's to its end.
#[tokio::test]
async fn iroh_a_session_carries_its_stream_floor_finished() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    let limit = StreamLimit::Limited(StreamEnd::Finished);
    a_session_carries_its_stream_floor(sender, receiver, limit).await;
}

/// As above, but each side drops both halves of a stream unread, the way a caller abandons one.
#[tokio::test]
async fn iroh_a_session_carries_its_stream_floor_dropped() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    let limit = StreamLimit::Limited(StreamEnd::Dropped);
    a_session_carries_its_stream_floor(sender, receiver, limit).await;
}

/// Aborting an iroh writer resets the QUIC stream, so the peer's read fails with `ConnectionReset`
/// rather than reading the clean end a drop gives.
#[tokio::test]
async fn iroh_an_aborted_writer_errors_the_peers_read() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    an_aborted_writer_errors_the_peers_read(sender, receiver).await;
}

/// A stream reset ends one stream, never the connection: a second stream still round-trips.
#[tokio::test]
async fn iroh_abort_leaves_the_sessions_other_streams_alive() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    abort_leaves_the_sessions_other_streams_alive(sender, receiver).await;
}

/// A second reset is harmless, and the reset writer refuses further writes.
#[tokio::test]
async fn iroh_abort_is_idempotent_and_writes_after_it_fail() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    abort_is_idempotent_and_writes_after_it_fail(sender, receiver).await;
}

/// Dropping an iroh writer without an abort still finishes the stream cleanly.
#[tokio::test]
async fn iroh_a_dropped_writer_still_ends_cleanly() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    a_dropped_writer_still_ends_cleanly(sender, receiver).await;
}

/// An abort after a successful shutdown does nothing, so the peer reads the clean end.
#[tokio::test]
async fn iroh_an_abort_after_shutdown_leaves_the_clean_end() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    an_abort_after_shutdown_leaves_the_clean_end(sender, receiver).await;
}

/// An abort ends one direction only: the peer's writes toward the aborter still arrive.
#[tokio::test]
async fn iroh_abort_leaves_the_streams_read_half_open() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    abort_leaves_the_streams_read_half_open(sender, receiver).await;
}

/// A close right after delivery costs the peer nothing: noq keeps bytes the peer acknowledged readable
/// after the connection closes, so a peer that starts reading only then still reads every byte and
/// the clean end. noq's docs do not promise this; this case is what holds it.
#[tokio::test]
async fn iroh_a_delivered_stream_survives_a_close() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    a_delivered_stream_survives_a_close(sender, receiver, Delivery::Acknowledged).await;
}

/// `delivered` on an aborted half fails with `ConnectionReset`.
#[tokio::test]
async fn iroh_delivered_after_an_abort_fails() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    delivered_after_an_abort_fails(sender, receiver).await;
}

/// `delivered` on a half never shut down finishes the stream, and the peer reads a clean end.
#[tokio::test]
async fn iroh_delivered_finishes_an_open_stream() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    delivered_finishes_an_open_stream(sender, receiver).await;
}

/// `delivered` on a stream its session's close cut short fails with `ConnectionAborted`.
#[tokio::test]
async fn iroh_delivered_after_a_close_fails() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    delivered_after_a_close_fails(sender, receiver).await;
}

/// `delivered` on a stream whose peer dropped its read half unread fails with `BrokenPipe`.
#[tokio::test]
async fn iroh_delivered_to_a_stopped_reader_fails() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    delivered_to_a_stopped_reader_fails(sender, receiver).await;
}

/// A close while a delivery is still pending leaves the peer's read an error, never a clean end.
#[tokio::test]
async fn iroh_a_close_after_a_pending_delivery_errors_the_peer() {
    let receiver = Endpoint::bind_local().await.expect("bind receiver");
    let sender = dialing(&receiver).await;
    a_close_after_a_pending_delivery_errors_the_peer(sender, receiver, Delivery::Acknowledged)
        .await;
}
