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

use core::future::poll_fn;
use core::net::SocketAddr;
use core::task::Poll;
use std::collections::VecDeque;

use bifrost::{Addr, Discovery, Error, Node, NodeId, Path, Session, Transport};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A message sent to a peer reached by key over a bidirectional stream echoes back byte-identical.
///
/// Exercises the whole reach contract: discovery finds the target, the transport establishes a
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

/// Whether a transport's [`Session::close`] reaches the peer yet.
///
/// Every transport must say, so a gap is recorded where it is run, with its owner, and never skipped in
/// silence.
#[derive(Clone, Copy, Debug)]
pub enum PeerNotice {
    /// The peer learns of the close: its reads on the session's streams error and its `wait_closed`
    /// resolves. The contract.
    Told,
    /// The transport cannot tell the peer yet, for the named reason and owner. The peer-side checks are
    /// not run; every local one is.
    NotYet(&'static str),
}

/// How long a closed session's streams have to fail. Generous: this bounds a hang, not a latency.
const CLOSE_BOUND: core::time::Duration = core::time::Duration::from_secs(5);

/// [`Session::close`] ends every stream on the session, whoever holds it, and with an error, never a
/// clean end.
///
/// The shape is the one a cut takes: the receiver moves a stream's halves into a detached task that
/// keeps holding them, keeps its session value alive, and closes it. Then, within a bound: the held
/// read fails rather than reading end-of-stream, a second close is harmless, `open_bi` fails, and (where
/// the transport can tell the peer) the dialer's read fails and its `wait_closed` resolves. A transport
/// whose streams outlive a close fails here, which is what a no-op close is. Panics with a descriptive
/// message on failure, so it reads as a test assertion.
pub async fn close_ends_held_streams<T, D>(sender: Node<T, D>, receiver: T, peer: PeerNotice)
where
    T: Transport,
    D: Discovery,
    <T::Session as Session>::Read: 'static,
    <T::Session as Session>::Write: 'static,
{
    let target = receiver.node_id();
    let dialing = async {
        let session = sender.connect(target).await.expect("connect");
        let (mut send, recv) = session.open_bi().await.expect("open stream");
        // Some transports announce a stream only once it carries a byte.
        send.write_all(b"held").await.expect("write");
        send.flush().await.expect("flush");
        (session, send, recv)
    };
    let accepting = async {
        let session = receiver.accept().await.expect("accept session");
        let (send, recv) = session.accept_bi().await.expect("accept stream");
        (session, send, recv)
    };
    let ((dialed, _dialed_send, mut dialed_recv), (accepted, held_send, held_recv)) =
        tokio::join!(dialing, accepting);

    // The detached holder: it keeps both halves and reports how its read finally ended.
    let (ended_tx, ended_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _send = held_send;
        let _ = ended_tx.send(read_to_the_end(held_recv).await);
    });

    accepted.close();
    accepted.close();

    let held = tokio::time::timeout(CLOSE_BOUND, ended_rx)
        .await
        .expect("a stream held past a close must end, not outlive its session")
        .expect("the holder reports");
    assert!(
        held.is_err(),
        "a stream held past a close must fail, never read a clean end"
    );
    assert!(
        accepted.open_bi().await.is_err(),
        "a closed session opens no new stream"
    );

    if let PeerNotice::Told = peer {
        let dialer_read = tokio::time::timeout(CLOSE_BOUND, read_to_the_end(&mut dialed_recv))
            .await
            .expect("the peer's stream must end when the session is closed");
        assert!(
            dialer_read.is_err(),
            "the peer's stream fails on a close, never reads a clean end"
        );
        tokio::time::timeout(CLOSE_BOUND, dialed.wait_closed())
            .await
            .expect("the peer's wait_closed resolves on a close");
    }
    sender.close().await;
}

/// Read `recv` until it errors or ends: `Err` for an error, `Ok` for a clean end.
async fn read_to_the_end(mut recv: impl tokio::io::AsyncRead + Unpin) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    loop {
        if recv.read(&mut buf).await? == 0 {
            return Ok(());
        }
    }
}

/// Whether a transport caps how many bidirectional streams a session holds at once.
///
/// Every transport states which, so the wait past a cap is checked where one exists.
#[derive(Clone, Copy, Debug)]
pub enum StreamLimit {
    /// The peer grants room for a capped number of streams. Past it [`Session::open_bi`] waits and never
    /// errors for being full, and it completes once fewer than 224 streams count. Held streams are ended
    /// the way the [`StreamEnd`] says.
    Limited(StreamEnd),
    /// The transport sets no stream count, so there is no wait to check.
    Unlimited,
}

/// How both sides end a held stream while a [`StreamLimit::Limited`] open waits.
///
/// Each is a way a caller lets a stream go, and each must hand its room back.
#[derive(Clone, Copy, Debug)]
pub enum StreamEnd {
    /// Each side finishes its writer and reads the other's to its end.
    Finished,
    /// Each side drops both halves unread, and nothing else on the session reads while it does.
    Dropped,
}

/// The streams every session carries at once, the floor the [`Session::open_bi`] contract promises.
const FLOOR: usize = 224;

/// The most streams a [`StreamLimit::Limited`] session may open before one waits. Far past any cap a
/// transport sets today; it turns a cap that never binds into a failure rather than a hang.
const MOST_OPENS: usize = 512;

/// How long one session's run of the case may take. Generous: this turns a transport that stops short
/// of the floor into a failure rather than a hang, and bounds nothing tighter.
const STREAMS_BOUND: core::time::Duration = core::time::Duration::from_secs(30);

/// How long an open must stay pending to count as waiting. Every held stream has already carried a
/// byte both ways, so any stream credit the peer would grant has had a round trip to arrive; this is a
/// short margin past that, not a latency budget.
const PENDING_FOR: core::time::Duration = core::time::Duration::from_millis(250);

/// How long a waiting open has to complete once fewer than [`FLOOR`] streams count. Shorter than
/// [`STREAMS_BOUND`], so an open that never completes fails here and names itself. Generous: this
/// bounds a hang, not a latency.
const OPEN_BOUND: core::time::Duration = core::time::Duration::from_secs(5);

/// One session carries 224 concurrent bidirectional streams, each moving a byte both ways, and
/// stays open.
///
/// Every stream is held live on both ends: a stream dropped early would hand its room back and let a
/// transport that carries fewer pass. With [`StreamLimit::Limited`], the dialer keeps opening
/// until an open waits, then ends held streams one at a time, oldest first, as the [`StreamEnd`]
/// says. The waiting open must complete by the end that leaves 223 counted; it may complete
/// sooner, and nothing is asserted about earlier ends. It then carries a byte both ways. Panics with
/// a descriptive message on failure, so it reads as a test assertion.
pub async fn a_session_carries_its_stream_floor<T, D>(
    sender: Node<T, D>,
    receiver: T,
    limit: StreamLimit,
) where
    T: Transport,
    D: Discovery,
{
    let target = receiver.node_id();
    // The dialer alone knows when a stream opens and when one ends, so it steps the acceptor through a
    // channel rather than the acceptor reading for cues: the dropped arm must not read while it ends.
    let (steps, mut next_step) = tokio::sync::mpsc::unbounded_channel();

    let accepting = async {
        let session = receiver.accept().await.expect("accept session");
        let mut held = VecDeque::new();
        while let Some(step) = next_step.recv().await {
            match step {
                Step::Accept => {
                    let (mut send, mut recv) = session.accept_bi().await.expect("accept stream");
                    echo_one(&mut send, &mut recv).await;
                    held.push_back((send, recv));
                }
                Step::End(how, ended) => {
                    let stream = held.pop_front().expect("the dialer ends a held stream");
                    how.end(stream).await;
                    // The send fails only if the dialer has already failed, and its own panic reports that.
                    let _ = ended.send(());
                }
            }
        }
        (session, held)
    };
    let dialing = async {
        let session = sender.connect(target).await.expect("connect");
        let mut held = Held::default();
        for _ in 0..FLOOR {
            let stream = session.open_bi().await.expect("open stream");
            held.carry(&steps, stream).await;
        }
        if let StreamLimit::Limited(how) = limit {
            // Boxed so the open that waits is the same one that later completes, out of the loop.
            let mut waiting = loop {
                let mut open = Box::pin(session.open_bi());
                let Ok(stream) = tokio::time::timeout(PENDING_FOR, open.as_mut()).await else {
                    break open;
                };
                assert!(
                    held.streams.len() < MOST_OPENS,
                    "an open waits before {MOST_OPENS} streams are held"
                );
                held.carry(&steps, stream.expect("open stream")).await;
            };

            // Ends before the one that leaves `FLOOR - 1` counted may free room early; that is allowed
            // and not required, so each is checked without waiting.
            let ends = held.streams.len() - (FLOOR - 1);
            let mut opened = None;
            for _ in 1..ends {
                held.end(&steps, how).await;
                opened = now(waiting.as_mut()).await;
                if opened.is_some() {
                    break;
                }
            }
            let stream = match opened {
                Some(stream) => stream,
                None => {
                    held.end(&steps, how).await;
                    tokio::time::timeout(OPEN_BOUND, waiting)
                        .await
                        .expect("a waiting open completes once fewer than the floor count")
                }
            };
            held.carry(&steps, stream.expect("open the waiting stream"))
                .await;
        }
        // Ending the step channel ends the acceptor's loop.
        drop(steps);
        (session, held)
    };

    let ((accepted, _accepted_streams), (dialed, _dialed_streams)) =
        tokio::time::timeout(STREAMS_BOUND, async { tokio::join!(accepting, dialing) })
            .await
            .expect("one session carries its stream floor");
    // A closed session never reopens, so open at the end means open at every count before it.
    assert!(
        now(core::pin::pin!(dialed.wait_closed())).await.is_none(),
        "the dialer's session stays open across its streams"
    );
    assert!(
        now(core::pin::pin!(accepted.wait_closed())).await.is_none(),
        "the acceptor's session stays open across its streams"
    );
    sender.close().await;
}

/// What the dialer tells the acceptor to do next.
enum Step {
    /// Accept the stream the dialer just opened, and echo its byte.
    Accept,
    /// End the oldest held stream this way, then say so.
    End(StreamEnd, tokio::sync::oneshot::Sender<()>),
}

/// The dialer's held streams, oldest first, and the byte the next one carries.
struct Held<W, R> {
    streams: VecDeque<(W, R)>,
    /// Each stream carries the byte after the last one's, so a crossed echo reads as a mismatch.
    byte: u8,
}

impl<W, R> Default for Held<W, R> {
    fn default() -> Self {
        Self {
            streams: VecDeque::new(),
            byte: 0,
        }
    }
}

impl<W, R> Held<W, R>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    /// Have the acceptor take a freshly opened stream, move a byte both ways on it, and hold it.
    async fn carry(&mut self, steps: &tokio::sync::mpsc::UnboundedSender<Step>, stream: (W, R)) {
        let (mut send, mut recv) = stream;
        steps.send(Step::Accept).expect("the acceptor takes steps");
        round_trip_one(&mut send, &mut recv, self.byte).await;
        self.byte = self.byte.wrapping_add(1);
        self.streams.push_back((send, recv));
    }

    /// End the oldest held stream on both sides, and return once both have.
    async fn end(&mut self, steps: &tokio::sync::mpsc::UnboundedSender<Step>, how: StreamEnd) {
        let stream = self
            .streams
            .pop_front()
            .expect("an open waits only while streams are held");
        let (ended, acceptor_ended) = tokio::sync::oneshot::channel();
        steps
            .send(Step::End(how, ended))
            .expect("the acceptor takes steps");
        how.end(stream).await;
        acceptor_ended.await.expect("the acceptor ends its side");
    }
}

impl StreamEnd {
    /// End one side's halves of a stream.
    async fn end(
        self,
        (mut send, recv): (
            impl tokio::io::AsyncWrite + Unpin,
            impl tokio::io::AsyncRead + Unpin,
        ),
    ) {
        match self {
            Self::Finished => {
                send.shutdown().await.expect("finish a held stream");
                read_to_the_end(recv)
                    .await
                    .expect("a held stream ends cleanly");
            }
            Self::Dropped => drop((send, recv)),
        }
    }
}

/// Write `byte` on a fresh stream and read it echoed back.
async fn round_trip_one(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    byte: u8,
) {
    // Some transports announce a stream only once it carries a byte, so the write goes first.
    send.write_all(&[byte]).await.expect("write a byte");
    send.flush().await.expect("flush the byte");
    let mut echoed = [0u8; 1];
    recv.read_exact(&mut echoed).await.expect("read the echo");
    assert_eq!(echoed, [byte], "a stream's echo matches its byte");
}

/// Read one byte from a fresh stream and write it back.
async fn echo_one(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
) {
    let mut byte = [0u8; 1];
    recv.read_exact(&mut byte).await.expect("read a byte");
    send.write_all(&byte).await.expect("echo the byte");
    send.flush().await.expect("flush the echo");
}

/// Poll `future` once, without waiting: its output if it is already ready.
async fn now<F: Future>(mut future: core::pin::Pin<&mut F>) -> Option<F::Output> {
    poll_fn(|cx| {
        Poll::Ready(match future.as_mut().poll(cx) {
            Poll::Ready(output) => Some(output),
            Poll::Pending => None,
        })
    })
    .await
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
