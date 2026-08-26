//! Parity conformance for Bifrost transports.
//!
//! bifrost is REACH: reach a peer by key over a pluggable transport. That is its one contract, and
//! this is the check every transport must pass. A composed [`Node`] dials the receiver by key, opens
//! a stream, and bytes echo back byte-identical. Transfer, hashing, files: not bifrost's job, not
//! tested here. iroh (QUIC) and the in-process mem transport both pass it unchanged.

// This crate is test scaffolding: every public function is a conformance assertion invoked from other
// crates' tests, so `expect` is the assertion mechanism, not production error handling.
#![allow(clippy::expect_used)]

use bifrost::{Discovery, Node, Session, Transport};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A message sent to a peer reached by key over a bidirectional stream echoes back byte-identical.
///
/// Exercises the whole reach contract: discovery resolves the target, the transport establishes a
/// session, a bidirectional stream carries bytes both ways, and the session closes cleanly. Panics
/// with a descriptive message on failure, so it reads as a test assertion.
pub async fn reach_roundtrip<T, D>(sender: Node<T, D>, receiver: T)
where
    T: Transport,
    D: Discovery,
{
    let target = receiver.node_id();
    let message = b"the bridge between realms".repeat(1024);

    let echo = async {
        let session = receiver.accept().await.expect("accept session");
        let (mut send, mut recv) = session.accept_bi().await.expect("accept stream");
        let mut buf = vec![0u8; message.len()];
        recv.read_exact(&mut buf).await.expect("read request");
        send.write_all(&buf).await.expect("write echo");
        send.shutdown().await.expect("finish echo");
        session.wait_closed().await;
    };
    let request = async {
        let session = sender.connect(target).await.expect("connect");
        let (mut send, mut recv) = session.open_bi().await.expect("open stream");
        send.write_all(&message).await.expect("write request");
        send.shutdown().await.expect("finish request");
        let mut echoed = vec![0u8; message.len()];
        recv.read_exact(&mut echoed).await.expect("read echo");
        sender.close().await;
        echoed
    };

    let ((), echoed) = tokio::join!(echo, request);
    assert_eq!(echoed, message, "echo matches the request");
}

/// A sender that writes, finishes, and closes immediately still delivers every byte to the receiver,
/// which observes a clean stream end.
///
/// This is the close/drain contract, distinct from [`reach_roundtrip`]: the sender does not wait for
/// any echo or acknowledgement, it shuts the write half and returns. A transport whose close is
/// asynchronous and lossy (its FIN can be dropped, its buffered data discarded on close) fails this
/// where it passes the lossless echo, because nothing here reads back to confirm delivery except the
/// receiver draining to EOF. Panics with a descriptive message on failure, so it reads as an assertion.
pub async fn close_drains<T, D>(sender: Node<T, D>, receiver: T)
where
    T: Transport,
    D: Discovery,
{
    let target = receiver.node_id();
    let message = b"the bridge between realms".repeat(1024);

    let drain = async {
        let session = receiver.accept().await.expect("accept session");
        let (_send, mut recv) = session.accept_bi().await.expect("accept stream");
        // Read to end: the sender never echoes, so a clean EOF here is the only proof the bytes and the
        // stream terminator both survived the sender closing right after the last write.
        let mut received = Vec::new();
        recv.read_to_end(&mut received)
            .await
            .expect("read to clean end");
        received
    };
    let send_then_close = async {
        let session = sender.connect(target).await.expect("connect");
        let (mut send, _recv) = session.open_bi().await.expect("open stream");
        send.write_all(&message).await.expect("write request");
        send.shutdown().await.expect("finish request");
        // Drain in-flight data before tearing the session down, then close the endpoint. A no-op
        // close over a transport that has not yet delivered would truncate the receiver.
        session.wait_closed().await;
        sender.close().await;
    };

    let (received, ()) = tokio::join!(drain, send_then_close);
    assert_eq!(
        received, message,
        "receiver drained every byte to a clean end"
    );
}
