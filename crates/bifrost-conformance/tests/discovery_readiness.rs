//! The dial path's discovery readiness seam.
//!
//! mDNS answers only after its first browse cycle, and a fresh browser often hears its OWN
//! advertisement echoed back before it hears the peer. These tests pin the dial path's response with
//! deterministic doubles: an empty first resolve waits for readiness FOR THE TARGET, a self record
//! does not release it, and a resolve that already yielded a hint does not wait at all. The doubles
//! stand in for the real service; mDNS's own timing belongs to the live-run gate, and the real
//! filter is pinned separately by the paused-clock tests in `bifrost-mdns`.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use bifrost::{
    Addr, Announced, CryptoKind, Discovery, Error, Layered, Node, NodeId, Session, StaticDiscovery,
    Transport,
};
use tokio::io;

/// A cold source whose first observation is the dialing node's own advertisement echoed back, and
/// whose second is the target's. Readiness carries the target, so only a wait asked for the target
/// lets the target's record land; a target-blind or never-asked wait leaves the dial empty.
#[derive(Clone)]
struct SelfFirstDiscovery {
    target: NodeId,
    addr: SocketAddr,
    /// Identity observations for the dialing node itself, which must not release a wait.
    self_records: Arc<AtomicUsize>,
    /// Target observations, which do.
    target_records: Arc<AtomicUsize>,
    /// The identity the dial asked readiness for, if it asked at all.
    ready_for: Arc<Mutex<Option<NodeId>>>,
    /// The last bound a wait was given, in milliseconds.
    bound_ms: Arc<AtomicU64>,
}

impl SelfFirstDiscovery {
    fn new(target: NodeId, addr: SocketAddr) -> Self {
        Self {
            target,
            addr,
            self_records: Arc::new(AtomicUsize::new(0)),
            target_records: Arc::new(AtomicUsize::new(0)),
            ready_for: Arc::new(Mutex::new(None)),
            bound_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn self_records(&self) -> usize {
        self.self_records.load(Ordering::SeqCst)
    }

    fn target_records(&self) -> usize {
        self.target_records.load(Ordering::SeqCst)
    }

    fn ready_for(&self) -> Option<NodeId> {
        *self
            .ready_for
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn bound(&self) -> Duration {
        Duration::from_millis(self.bound_ms.load(Ordering::SeqCst))
    }
}

impl Discovery for SelfFirstDiscovery {
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        let heard = self.target_records.load(Ordering::SeqCst) > 0;
        Ok(if node == self.target && heard {
            vec![self.addr]
        } else {
            Vec::new()
        })
    }

    async fn wait_ready(&self, node: NodeId, timeout: Duration) {
        self.bound_ms
            .store(timeout.as_millis() as u64, Ordering::SeqCst);
        *self
            .ready_for
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(node);
        // The dialing node's own advertisement echoes back first: an observation of a DIFFERENT
        // identity, which a target-aware wait must hold through.
        self.self_records.fetch_add(1, Ordering::SeqCst);
        // The target's record lands next, and only a wait asked for the target lets it through.
        tokio::task::yield_now().await;
        if node == self.target {
            self.target_records.fetch_add(1, Ordering::SeqCst);
        }
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

/// The dial's own record arrives first. A target-aware wait holds through it, lets the target's
/// record land, and only then the re-resolve reaches the peer; a target-blind release would leave
/// the hint set empty and the transport would refuse the dial.
#[tokio::test]
async fn self_record_first_still_waits_for_the_target_then_dials() {
    let peer = id(0x11);
    let addr = addr(7001);
    let cold = SelfFirstDiscovery::new(peer, addr);
    let probe = cold.clone();

    let transport = RecordingTransport::default();
    let dialed = transport.dialed.clone();
    let node = Node::new(transport, Layered::new(StaticDiscovery::new(), cold));

    node.connect(peer)
        .await
        .expect("a cold no-hint dial reaches the peer after the wait");

    assert_eq!(
        probe.ready_for(),
        Some(peer),
        "readiness must be asked for the dialed identity"
    );
    assert_eq!(
        probe.self_records(),
        1,
        "the dialing node's own record arrived first"
    );
    assert_eq!(
        probe.target_records(),
        1,
        "only the target record releases the wait"
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
    let cold = SelfFirstDiscovery::new(peer, addr(7003));
    let probe = cold.clone();

    let transport = RecordingTransport::default();
    let dialed = transport.dialed.clone();
    let node = Node::new(transport, Layered::new(hints, cold));

    node.connect(peer)
        .await
        .expect("a hinted dial reaches the peer at once");

    assert_eq!(
        probe.ready_for(),
        None,
        "a resolve with hints must not wait for another source"
    );
    assert_eq!(
        probe.self_records(),
        0,
        "no readiness wait means no observation is consumed"
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
