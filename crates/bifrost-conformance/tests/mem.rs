use bifrost::{NoDiscovery, Node, Transport};
use bifrost_conformance::{
    Delivery, StreamLimit, a_close_after_a_pending_delivery_errors_the_peer,
    a_delivered_stream_survives_a_close, a_dropped_writer_still_ends_cleanly,
    a_session_carries_its_stream_floor, abort_is_idempotent_and_writes_after_it_fail,
    abort_leaves_the_sessions_other_streams_alive, abort_leaves_the_streams_read_half_open,
    an_abort_after_shutdown_leaves_the_clean_end, an_aborted_writer_errors_the_peers_read,
    an_empty_read_is_not_the_end, close_drains, close_ends_held_streams,
    delivered_after_a_close_fails, delivered_after_an_abort_fails,
    delivered_finishes_an_open_stream, delivered_to_a_stopped_reader_fails,
    delivered_waits_for_the_peers_read, identity_binding, reach_roundtrip, unknown_conn_info,
    wrong_key_rejected,
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
/// [`bifrost::NodeId`], so the key dialed is the key reached. Nothing is proved: mem has no handshake,
/// and every identity's secret is computable.
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
    close_ends_held_streams(sender, receiver).await;
}

/// One in-process session carries the stream floor. Streams ride unbounded channels, so the transport
/// has no count to stop at and no wait to check.
#[tokio::test]
async fn mem_a_session_carries_its_stream_floor() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    a_session_carries_its_stream_floor(sender, receiver, StreamLimit::Unlimited).await;
}

/// Aborting an in-process writer fires that direction's own signal, so the peer's read fails with
/// `ConnectionReset` rather than reading the clean end a drop gives.
#[tokio::test]
async fn mem_an_aborted_writer_errors_the_peers_read() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    an_aborted_writer_errors_the_peers_read(sender, receiver).await;
}

/// An abort ends one direction of one stream, never the session: a second stream still round-trips.
#[tokio::test]
async fn mem_abort_leaves_the_sessions_other_streams_alive() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    abort_leaves_the_sessions_other_streams_alive(sender, receiver).await;
}

/// A second abort is harmless, and the aborted writer refuses further writes.
#[tokio::test]
async fn mem_abort_is_idempotent_and_writes_after_it_fail() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    abort_is_idempotent_and_writes_after_it_fail(sender, receiver).await;
}

/// Dropping an in-process writer without an abort still ends the stream cleanly.
#[tokio::test]
async fn mem_a_dropped_writer_still_ends_cleanly() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    a_dropped_writer_still_ends_cleanly(sender, receiver).await;
}

/// An abort after a successful shutdown does nothing, so the peer reads the clean end.
#[tokio::test]
async fn mem_an_abort_after_shutdown_leaves_the_clean_end() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    an_abort_after_shutdown_leaves_the_clean_end(sender, receiver).await;
}

/// An abort ends one direction only: the peer's writes toward the aborter still arrive.
#[tokio::test]
async fn mem_abort_leaves_the_streams_read_half_open() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    abort_leaves_the_streams_read_half_open(sender, receiver).await;
}

/// A close after delivery costs the peer nothing: here `delivered` resolves only once the peer has
/// read the end, because a close discards bytes the peer has not read.
#[tokio::test]
async fn mem_a_delivered_stream_survives_a_close() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    a_delivered_stream_survives_a_close(sender, receiver, Delivery::ReadToEnd).await;
}

/// `delivered` on an aborted half fails with `ConnectionReset`.
#[tokio::test]
async fn mem_delivered_after_an_abort_fails() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    delivered_after_an_abort_fails(sender, receiver).await;
}

/// `delivered` on a half never shut down finishes the stream, and the peer reads a clean end.
#[tokio::test]
async fn mem_delivered_finishes_an_open_stream() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    delivered_finishes_an_open_stream(sender, receiver).await;
}

/// `delivered` on a stream its session's close cut short fails with `ConnectionAborted`.
#[tokio::test]
async fn mem_delivered_after_a_close_fails() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    delivered_after_a_close_fails(sender, receiver).await;
}

/// `delivered` stays pending while the peer has not read, and resolves once it reads the end.
#[tokio::test]
async fn mem_delivered_waits_for_the_peers_read() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    delivered_waits_for_the_peers_read(sender, receiver).await;
}

/// `delivered` on a stream whose peer dropped its read half unread fails with `BrokenPipe`.
#[tokio::test]
async fn mem_delivered_to_a_stopped_reader_fails() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    delivered_to_a_stopped_reader_fails(sender, receiver).await;
}

/// A close while a delivery is still pending leaves the peer's read an error, never a clean end.
#[tokio::test]
async fn mem_a_close_after_a_pending_delivery_errors_the_peer() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    a_close_after_a_pending_delivery_errors_the_peer(sender, receiver, Delivery::ReadToEnd).await;
}

/// A read into an empty buffer is not the end of the stream, so it delivers nothing.
#[tokio::test]
async fn mem_an_empty_read_is_not_the_end() {
    let receiver = MemTransport::bind();
    let sender = Node::new(MemTransport::bind(), NoDiscovery);
    an_empty_read_is_not_the_end(sender, receiver).await;
}
