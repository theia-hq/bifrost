//! The dial path's discovery readiness seam.
//!
//! mDNS answers only after its first browse cycle, so a resolve that runs in the first milliseconds
//! of a cold node misses a peer that is on the network. These tests pin the dial path's response
//! with deterministic doubles: an empty first resolve waits for the source to become ready and then
//! resolves again, while a resolve that already yielded a hint does not wait at all. The doubles
//! stand in for the real service; mDNS's own timing belongs to the live-run gate.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use bifrost::{
    Addr, Announced, CryptoKind, Discovery, Error, Layered, Node, NodeId, Session, StaticDiscovery,
    Transport,
};
use tokio::io;

/// A cold source: every resolve misses until a readiness wait stands in for its first browse cycle,
/// after which it answers. Deterministic, it never sleeps.
#[derive(Clone)]
struct ColdDiscovery {
    peer: NodeId,
    addr: SocketAddr,
    /// Set by the wait, standing in for the browse cycle having run.
    heard: Arc<AtomicBool>,
    /// Readiness waits observed, so a test can prove the dial path did or did not warm the source.
    waits: Arc<AtomicUsize>,
    /// The last bound a wait was given, in milliseconds.
    bound_ms: Arc<AtomicU64>,
}

impl ColdDiscovery {
    fn new(peer: NodeId, addr: SocketAddr) -> Self {
        Self {
            peer,
            addr,
            heard: Arc::new(AtomicBool::new(false)),
            waits: Arc::new(AtomicUsize::new(0)),
            bound_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn waits(&self) -> usize {
        self.waits.load(Ordering::SeqCst)
    }

    fn bound(&self) -> Duration {
        Duration::from_millis(self.bound_ms.load(Ordering::SeqCst))
    }
}

impl Discovery for ColdDiscovery {
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        Ok(if node == self.peer && self.heard.load(Ordering::SeqCst) {
            vec![self.addr]
        } else {
            Vec::new()
        })
    }

    async fn wait_ready(&self, timeout: Duration) {
        self.waits.fetch_add(1, Ordering::SeqCst);
        self.bound_ms
            .store(timeout.as_millis() as u64, Ordering::SeqCst);
        self.heard.store(true, Ordering::SeqCst);
    }
}

/// The hints a [`RecordingTransport`] was last dialed with, shared with the test after the transport
/// moves into the node.
#[derive(Clone, Default)]
struct DialLog(Arc<Mutex<Option<Addr>>>);

impl DialLog {
    fn hints(&self) -> Vec<SocketAddr> {
        let dialed = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        dialed
            .as_ref()
            .map(|addr| addr.hints.clone())
            .unwrap_or_default()
    }
}

/// Why a hint-less dial is refused: a direct-only backend cannot dial an identity alone.
#[derive(Debug)]
struct NoHints;

impl core::fmt::Display for NoHints {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no direct address hint")
    }
}

impl core::error::Error for NoHints {}

/// A transport that records the address it was dialed with and refuses a hint-less dial the way a
/// direct-only backend does, so a dial that skipped the readiness wait fails instead of passing.
#[derive(Default)]
struct RecordingTransport {
    dialed: DialLog,
}

impl Transport for RecordingTransport {
    type Security = Announced;
    type Session = RecordingSession;

    fn node_id(&self) -> NodeId {
        id(0x33)
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(self.node_id())
    }

    async fn connect(&self, addr: Addr) -> Result<RecordingSession, Error> {
        if addr.hints.is_empty() {
            return Err(Error::Connect(Box::new(NoHints)));
        }
        let mut dialed = self
            .dialed
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *dialed = Some(addr.clone());
        Ok(RecordingSession { peer: addr.node })
    }

    async fn accept(&self) -> Result<RecordingSession, Error> {
        Ok(RecordingSession {
            peer: self.node_id(),
        })
    }

    async fn close(&self) {}
}

/// A session that carries only the dialed identity; these tests never open a stream.
struct RecordingSession {
    peer: NodeId,
}

impl Session for RecordingSession {
    type Security = Announced;
    type Write = io::Sink;
    type Read = io::Empty;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn accept_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn wait_closed(&self) {}
}

/// A cold source's first resolve misses, so the dial waits for readiness, resolves again, and only
/// then reaches the peer. Without the wait, the transport would refuse the empty hint set.
#[tokio::test]
async fn cold_resolve_waits_then_dials() {
    let peer = id(0x11);
    let addr = addr(7001);
    let cold = ColdDiscovery::new(peer, addr);
    let probe = cold.clone();

    let transport = RecordingTransport::default();
    let dialed = transport.dialed.clone();
    let node = Node::new(transport, Layered::new(StaticDiscovery::new(), cold));

    node.connect(peer)
        .await
        .expect("a cold no-hint dial reaches the peer after the wait");

    assert_eq!(
        probe.waits(),
        1,
        "the dial warms the cold source exactly once"
    );
    let bound = probe.bound();
    assert!(
        bound <= Duration::from_secs(2),
        "the readiness bound stays small, got {bound:?}"
    );
    assert_eq!(
        dialed.hints(),
        vec![addr],
        "the hint learned during the wait is what the transport was dialed with"
    );
}

/// A resolve that already yielded a hint dials at once: the background source is never warmed, so a
/// static hint does not pay the readiness bound.
#[tokio::test]
async fn hinted_resolve_does_not_wait() {
    let peer = id(0x22);
    let hinted = addr(7002);
    let mut hints = StaticDiscovery::new();
    hints.insert(peer, vec![hinted]);

    // This source would answer the peer if warmed; the test proves the dial never asked it to.
    let cold = ColdDiscovery::new(peer, addr(7003));
    let probe = cold.clone();

    let transport = RecordingTransport::default();
    let dialed = transport.dialed.clone();
    let node = Node::new(transport, Layered::new(hints, cold));

    node.connect(peer)
        .await
        .expect("a hinted dial reaches the peer at once");

    assert_eq!(
        probe.waits(),
        0,
        "a resolve with hints must not wait for another source"
    );
    assert_eq!(
        dialed.hints(),
        vec![hinted],
        "the hand-fed hint is dialed, not a learned one"
    );
}

/// A distinct ed25519 [`NodeId`] seeded by one byte, enough to tell test identities apart.
fn id(seed: u8) -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [seed; NodeId::KEY_LEN])
}

/// A loopback socket address on the given port.
fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
