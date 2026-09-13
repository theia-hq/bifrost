//! Conformance for Bifrost transports.
//!
//! bifrost is REACH: reach a peer by key over a pluggable transport. That is its one contract, and
//! this is the check every transport must pass. A composed [`Node`] dials the receiver by key, opens
//! a stream, and bytes echo back byte-identical; a sender that closes right after its last write
//! still drains; `conn_info` reports only what the transport knows. Identity is checked where a
//! black-box test can: a session attributes the dialed key on both ends ([`identity_binding`]), and
//! a dial to a fabricated key at the receiver's real address yields no session
//! ([`wrong_key_rejected`]).
//!
//! What this suite cannot prove, stated plainly. Identity attribution is falsified for a fabricating
//! transport, never proven for an honest one. The suite inspects no artifacts, so it cannot tell a
//! sealed channel from a plaintext one: the channel guarantee rests on the backing implementation
//! (iroh inherits QUIC and TLS, which this suite does not exercise) and on protocol review. Forward
//! secrecy, nonce discipline, replay resistance against an active attacker, and entropy quality are
//! protocol review of the handshake and its library, not black-box assertions. iroh (QUIC), the
//! in-process mem transport, and quirk all pass the suite unchanged; that is the byte contract plus
//! the identity cases, and the security profile is what each backend declares beside them.

// This crate is test scaffolding: every public function is a conformance assertion invoked from other
// crates' tests, so `expect` is the assertion mechanism, not production error handling.
#![allow(clippy::expect_used)]

use bifrost::{Addr, Discovery, Error, Node, NodeId, Path, Session, Transport};
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

/// A session attributes the dialed identity on both ends: the dialer's [`Session::peer`] is the key
/// it dialed, and the acceptor's is the dialer's own identity.
///
/// A transport that fabricates `peer()` passes the byte-parity cases and fails here. Panics with a
/// descriptive message on failure, so it reads as a test assertion.
pub async fn identity_binding<T: Transport>(sender: T, receiver: T) {
    let target = receiver.node_id();
    let dialer = sender.node_id();
    let addr = Addr {
        node: target,
        hints: receiver.local_addr().hints,
    };

    let (dialed, accepted) = tokio::join!(sender.connect(addr), receiver.accept());
    let dialed = dialed.expect("connect");
    let accepted = accepted.expect("accept");
    assert_eq!(
        dialed.peer(),
        target,
        "the dialer attributes the key it dialed"
    );
    assert_eq!(
        accepted.peer(),
        dialer,
        "the acceptor attributes the dialer's identity"
    );

    sender.close().await;
}

/// A dial to a fabricated identity at the receiver's real address yields no session.
///
/// The strongest identity statement a black-box test can make: a transport that accepts whatever key
/// it is handed, or answers with a session for a key the receiver does not hold, fails here. Panics
/// with a descriptive message on failure, so it reads as a test assertion.
pub async fn wrong_key_rejected<T: Transport>(sender: T, receiver: T, fabricated: NodeId) {
    let target = receiver.node_id();
    assert_ne!(
        fabricated, target,
        "the fabricated key must differ from the receiver's"
    );
    let addr = Addr {
        node: fabricated,
        hints: receiver.local_addr().hints,
    };

    match sender.connect(addr).await {
        Err(Error::Connect(_)) => {}
        Err(other) => panic!("expected a connect error, got {other:?}"),
        Ok(_) => panic!("connect yielded a session for an identity that was never reached"),
    }

    sender.close().await;
}

/// A direct transport reports [`Path::Direct`] and names the remote over an established session.
///
/// This is the `conn_info` contract for a transport with no relay in the path (quirk today, iroh over
/// loopback): the dialer's session must report the current path as [`Path::Direct`] and carry a remote
/// socket address, since that is exactly the reassuring "am I peer-to-peer?" answer a status readout
/// renders. Panics with a descriptive message on failure, so it reads as a test assertion.
pub async fn direct_conn_info<T, D>(sender: Node<T, D>, receiver: T)
where
    T: Transport,
    D: Discovery,
{
    let target = receiver.node_id();
    let accepting = async { receiver.accept().await.expect("accept session") };
    let dialing = async { sender.connect(target).await.expect("connect") };
    let (_accepted, session) = tokio::join!(accepting, dialing);

    let info = session.conn_info();
    assert_eq!(
        info.path,
        Path::Direct,
        "a direct transport reports a direct path, got {:?}",
        info.path
    );
    assert!(
        info.remote.is_some(),
        "a direct path names its remote address, got none"
    );

    sender.close().await;
}

/// A transport that does not expose its path reports the [`Path::Unknown`] default with no remote.
///
/// This pins the additive, best-effort contract: an uninstrumented transport (in-process mem) inherits
/// the trait default rather than fabricating a path, so `conn_info` is honest about what it cannot know.
/// Panics with a descriptive message on failure, so it reads as a test assertion.
pub async fn unknown_conn_info<T, D>(sender: Node<T, D>, receiver: T)
where
    T: Transport,
    D: Discovery,
{
    let target = receiver.node_id();
    let accepting = async { receiver.accept().await.expect("accept session") };
    let dialing = async { sender.connect(target).await.expect("connect") };
    let (_accepted, session) = tokio::join!(accepting, dialing);

    let info = session.conn_info();
    assert_eq!(
        info.path,
        Path::Unknown,
        "an uninstrumented transport reports Unknown, got {:?}",
        info.path
    );
    assert!(
        info.remote.is_none() && info.rtt.is_none(),
        "an unknown path carries no remote or rtt"
    );

    sender.close().await;
}
