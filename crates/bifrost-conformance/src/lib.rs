//! Conformance for Bifrost transports.
//!
//! bifrost is REACH: reach a peer by key over a pluggable transport. That is its one contract, and
//! this is the check every transport must pass. A composed [`Node`] dials the receiver by key, opens
//! a stream, and bytes echo back byte-identical; a sender that closes right after its last write
//! still drains; `conn_info` reports only what the transport knows; a transport that binds sockets
//! reports them as bound, wildcard and all ([`bound_sockets_are_bind_truth`],
//! [`wildcard_bind_is_not_rewritten`]). Identity is checked where a
//! black-box test can: a session attributes the dialed key on both ends ([`identity_binding`]), and
//! a dial to a fabricated key at the receiver's real address yields no session
//! ([`wrong_key_rejected`]).
//!
//! What this suite cannot prove, stated plainly. The assertions pass for a transport that echoes the
//! dialed key back without proving it, so they falsify a mis-attributing fabricator, never prove an
//! honest transport. Where the wire can be driven by a hostile peer,
//! [`claimed_identity_not_attributed`] is the accept-side case: a dialer presenting a foreign
//! `NodeId` is refused or attributed its true key, never the claim. The suite inspects no artifacts,
//! so it cannot tell a sealed channel from a plaintext one: the channel guarantee rests on the
//! backing implementation (iroh inherits QUIC and TLS, which this suite does not exercise) and on
//! protocol review. Forward secrecy, nonce discipline, replay resistance against an active
//! attacker, and entropy quality are protocol review of the handshake and its library, not
//! black-box assertions. iroh (QUIC), the in-process mem transport, and quirk all pass the suite
//! unchanged; that is the byte contract plus the identity cases, and the security profile is what
//! each backend declares beside them.

// This crate is test scaffolding: every public function is a conformance assertion invoked from other
// crates' tests, so `expect` is the assertion mechanism, not production error handling.
#![allow(clippy::expect_used)]

use core::net::SocketAddr;

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
/// This catches a transport whose attribution has no basis: a wrong constant, or a session created
/// for a key nobody reached. It does not catch a transport that echoes the dialed key back without
/// proving it; attribution consistency is not key possession. Panics with a descriptive message on
/// failure, so it reads as a test assertion.
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
/// This catches a transport that accepts the key it is handed, or answers with a session for a key
/// the receiver does not hold. A transport that refuses keys it has no endpoint for passes; the
/// accept-side case is [`claimed_identity_not_attributed`], where the wire can be driven. Panics
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

/// A dialer presenting an identity it does not hold is never attributed that identity.
///
/// `liar` dials `receiver` claiming `claimed`, a key that is neither endpoint's own. The receiver
/// must refuse the session or attribute its true peer, never `claimed`. This is the accept-side
/// case the shared assertions cannot reach: [`identity_binding`] passes for a transport that
/// echoes keys with no handshake, and [`wrong_key_rejected`] passes when the echoer refuses keys it
/// has no endpoint for. Run it where the transport's wire can be driven by a hostile peer (a
/// byte-carrying wrapper inner, a plaintext UDP handshake); a stack whose handshake lives inside a
/// dependency (iroh's RPK TLS) cannot be driven by a foreign claim at all, and that is the
/// guarantee itself, held by review of that stack rather than by this suite. The receiver's
/// `accept` is joined with the dial, so a transport whose handshake has no deadline can park here.
/// Panics with a descriptive message on failure, so it reads as a test assertion.
pub async fn claimed_identity_not_attributed<L, R>(liar: L, receiver: R, claimed: NodeId)
where
    L: Transport,
    R: Transport,
{
    assert_ne!(
        claimed,
        receiver.node_id(),
        "the claimed identity must differ from the receiver's"
    );
    assert_ne!(
        claimed,
        liar.node_id(),
        "the claimed identity must differ from the liar's own"
    );
    let addr = Addr {
        node: receiver.node_id(),
        hints: receiver.local_addr().hints,
    };

    let (accepted, _dialed) = tokio::join!(receiver.accept(), liar.connect(addr));
    if let Ok(session) = accepted {
        assert_ne!(
            session.peer(),
            claimed,
            "the acceptor attributed an identity the dialer never proved"
        );
    }

    liar.close().await;
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

/// A bound wire transport reports the sockets it actually bound.
///
/// The bind-truth contract where a black-box test can see it: a transport that owns sockets names at
/// least one, every socket it names carries the port the OS assigned (never the `0` that was asked
/// for), and the set agrees port-for-port with the hints `local_addr` derives from it. That last
/// check is what catches a transport reporting a set from somewhere else entirely, since the two
/// accessors must describe the same sockets and may differ only in how an unspecified IP is written.
/// A socketless transport (in-process) reports none and is not run through this. Panics with a
/// descriptive message on failure, so it reads as a test assertion.
pub fn bound_sockets_are_bind_truth<T: Transport>(transport: &T) {
    let bound = transport.bound_sockets();
    assert!(
        !bound.is_empty(),
        "a bound wire transport names at least one socket"
    );
    assert!(
        bound.iter().all(|socket| socket.port() != 0),
        "a bound socket carries the port the OS assigned, got {bound:?}"
    );

    // Family and port, not port alone: a transport that binds a v4 and a v6 socket on the same
    // ephemeral port would otherwise pass while reporting one family twice.
    let mut bound_sockets = families_and_ports(&bound);
    let mut hint_sockets = families_and_ports(&transport.local_addr().hints);
    bound_sockets.sort_unstable();
    hint_sockets.sort_unstable();
    assert_eq!(
        bound_sockets, hint_sockets,
        "the bound sockets and the local hints describe the same sockets"
    );
}

/// A transport bound to a wildcard address reports the unspecified IP, not loopback.
///
/// The case the whole accessor exists for: `local_addr` rewrites `0.0.0.0` to `127.0.0.1` so the
/// hint is dialable here, which makes a wildcard bind indistinguishable from a deliberate loopback
/// bind. A publisher must expand the first into the host's real addresses and must never expand the
/// second, so bind truth has to keep the wildcard. Run it against a transport the caller bound to a
/// wildcard; a transport bound to a fixed address has nothing to preserve. Panics with a descriptive
/// message on failure, so it reads as a test assertion.
pub fn wildcard_bind_is_not_rewritten<T: Transport>(transport: &T) {
    let bound = transport.bound_sockets();
    assert!(
        bound.iter().any(|socket| socket.ip().is_unspecified()),
        "a wildcard bind keeps its unspecified IP in bind truth, got {bound:?}"
    );
}

/// The family and port of each socket, the pair that identifies it independently of how an
/// unspecified IP is written.
fn families_and_ports(sockets: &[SocketAddr]) -> Vec<(bool, u16)> {
    sockets
        .iter()
        .map(|socket| (socket.is_ipv4(), socket.port()))
        .collect()
}
