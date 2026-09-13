use core::pin::Pin;
use core::sync::atomic::AtomicU32;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;
use std::sync::Arc;

use bifrost_core::{Addr, Error, NodeId};
use bifrost_transport::{Announced, Sealed, Secure, SecurityProfile, Session, Transport};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, ReadBuf};
use tokio::sync::mpsc;
use tokio::time;

use crate::error::NoiseError;
use crate::session::{Chunk, StreamLife, StreamRead, StreamWrite};
use crate::{MAX_HANDSHAKES, Noise, Wrappable};

/// Build a standalone stream lifetime not tied to a session, for stream-level tests.
fn standalone_life() -> Arc<StreamLife> {
    let live = Arc::new(AtomicU32::new(0));
    StreamLife::acquire(&live).expect("a free slot")
}

/// A transport with a real identity and no wire, for compile- and constructor-level assertions.
struct Fake {
    node: NodeId,
}

impl Transport for Fake {
    type Security = Announced;
    type Session = FakeSession;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(self.node)
    }

    async fn connect(&self, _addr: Addr) -> Result<FakeSession, Error> {
        Err(Error::Closed)
    }

    async fn accept(&self) -> Result<FakeSession, Error> {
        Err(Error::Closed)
    }

    async fn close(&self) {}
}

struct FakeSession;

impl Session for FakeSession {
    type Security = Announced;
    type Write = tokio::io::Sink;
    type Read = tokio::io::Empty;

    fn peer(&self) -> NodeId {
        NodeId::from_ed25519_secret(&[1u8; NodeId::KEY_LEN])
    }

    async fn open_bi(&self) -> Result<(tokio::io::Sink, tokio::io::Empty), Error> {
        Ok((tokio::io::sink(), tokio::io::empty()))
    }

    async fn accept_bi(&self) -> Result<(tokio::io::Sink, tokio::io::Empty), Error> {
        Ok((tokio::io::sink(), tokio::io::empty()))
    }

    async fn wait_closed(&self) {}
}

/// The wrapper declares `Sealed` for an `Announced` inner and satisfies `Secure`.
#[test]
fn wrapper_declares_sealed_and_is_secure() {
    let seed = [12u8; NodeId::KEY_LEN];
    let wrapper = Noise::new(
        Fake {
            node: NodeId::from_ed25519_secret(&seed),
        },
        seed,
    )
    .expect("wrap");
    assert_eq!(
        <Noise<Fake> as Transport>::Security::SECURITY,
        Sealed::SECURITY
    );
    fn secure<T: Transport>()
    where
        T::Security: Secure,
    {
    }
    secure::<Noise<Fake>>();
    assert_eq!(wrapper.node_id(), NodeId::from_ed25519_secret(&seed));
    fn wrappable<P: Wrappable>() {}
    wrappable::<Announced>();
    wrappable::<Sealed>();
}

/// The constructor refuses an inner transport bound under another identity.
#[test]
fn constructor_refuses_a_mismatched_identity() {
    let inner = Fake {
        node: NodeId::from_ed25519_secret(&[1u8; NodeId::KEY_LEN]),
    };
    assert!(matches!(
        Noise::new(inner, [2u8; NodeId::KEY_LEN]),
        Err(NoiseError::IdentityMismatch { .. })
    ));
}

/// A write parks when the stream's bounded queue is full, and proceeds once the queue drains.
#[tokio::test]
async fn stream_write_backpressures_when_its_queue_is_full() {
    let (tx, mut rx) = mpsc::channel(1);
    let mut write = StreamWrite::new(0, tx, standalone_life());

    let first = write
        .write(&[0u8; 128])
        .await
        .expect("the first frame fits");
    assert_eq!(first, 128);

    let blocked = time::timeout(Duration::from_millis(5), write.write(&[0u8; 1])).await;
    assert!(
        blocked.is_err(),
        "a full queue must park the write, not buffer without bound"
    );

    let _ = rx.recv().await.expect("the first frame is queued");
    let resumed = time::timeout(Duration::from_secs(1), write.write(&[0u8; 4])).await;
    assert!(resumed.is_ok(), "draining the queue wakes the write");
}

/// Reads split across buffers, report a peer reset as a connection reset, and end cleanly.
#[tokio::test]
async fn stream_read_handles_partial_buffers_reset_and_eof() {
    let (tx, rx) = mpsc::channel(4);
    let mut read = StreamRead::new(rx, standalone_life());

    tx.send(Chunk::Data(vec![1, 2, 3, 4, 5]))
        .await
        .expect("queue data");
    let mut small = [0u8; 2];
    assert_eq!(read.read(&mut small).await.expect("first read"), 2);
    assert_eq!(small, [1, 2]);
    let mut rest = [0u8; 4];
    let n = read.read(&mut rest).await.expect("second read");
    assert_eq!(&rest[..n], &[3, 4, 5]);

    tx.send(Chunk::Reset).await.expect("queue reset");
    let reset = read.read(&mut rest).await.expect_err("reset read fails");
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);

    drop(tx);
    let eof = read.read(&mut rest).await.expect("clean end");
    assert_eq!(eof, 0);
}

/// A peer that connects and stalls is dropped at the handshake deadline, not parked forever.
#[tokio::test(start_paused = true)]
async fn accept_times_out_on_a_stalled_peer() {
    let seed = [13u8; NodeId::KEY_LEN];
    let wrapper = Noise::new(Stalled, seed).expect("wrap");
    match wrapper.accept().await {
        Err(Error::Accept(source)) => assert!(
            matches!(
                source.downcast_ref::<NoiseError>(),
                Some(NoiseError::HandshakeTimeout)
            ),
            "the failure is the handshake deadline"
        ),
        Err(_) => panic!("expected an accept timeout"),
        Ok(_) => panic!("a stalled peer must not yield a session"),
    }
}

/// A listener runs at most `MAX_HANDSHAKES` accepts at once; further accepts wait for a slot, so a
/// flood cannot grow unbounded handshake state.
#[tokio::test(start_paused = true)]
async fn accept_waits_for_a_handshake_slot() {
    let seed = [13u8; NodeId::KEY_LEN];
    let wrapper = Arc::new(Noise::new(Stalled, seed).expect("wrap"));
    let held: Vec<_> = (0..MAX_HANDSHAKES)
        .map(|_| wrapper.handshakes.try_acquire().expect("handshake slot"))
        .collect();
    let accepting = tokio::spawn({
        let wrapper = Arc::clone(&wrapper);
        async move { wrapper.accept().await }
    });
    tokio::task::yield_now().await;
    assert!(
        !accepting.is_finished(),
        "accept waits for a handshake slot"
    );

    drop(held);
    match accepting.await.expect("join") {
        Err(Error::Accept(source)) => assert!(
            matches!(
                source.downcast_ref::<NoiseError>(),
                Some(NoiseError::HandshakeTimeout)
            ),
            "the stalled handshake hits its deadline"
        ),
        Err(_) => panic!("expected the handshake deadline"),
        Ok(_) => panic!("a stalled peer must not yield a session"),
    }
}

/// An inner that accepts and then never sends a byte.
struct Stalled;

impl Transport for Stalled {
    type Security = Announced;
    type Session = StalledSession;

    fn node_id(&self) -> NodeId {
        NodeId::from_ed25519_secret(&[13u8; NodeId::KEY_LEN])
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(self.node_id())
    }

    async fn connect(&self, _addr: Addr) -> Result<StalledSession, Error> {
        Ok(StalledSession)
    }

    async fn accept(&self) -> Result<StalledSession, Error> {
        Ok(StalledSession)
    }

    async fn close(&self) {}
}

struct StalledSession;

impl Session for StalledSession {
    type Security = Announced;
    type Write = tokio::io::Sink;
    type Read = Pending;

    fn peer(&self) -> NodeId {
        NodeId::from_ed25519_secret(&[14u8; NodeId::KEY_LEN])
    }

    async fn open_bi(&self) -> Result<(tokio::io::Sink, Pending), Error> {
        Ok((tokio::io::sink(), Pending))
    }

    async fn accept_bi(&self) -> Result<(tokio::io::Sink, Pending), Error> {
        Ok((tokio::io::sink(), Pending))
    }

    async fn wait_closed(&self) {}
}

/// A reader that never produces a byte.
struct Pending;

impl AsyncRead for Pending {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
