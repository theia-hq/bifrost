//! The dial path's discovery seam: what a subscription may and may not do to a dial.
//!
//! A scripted source stands in for a live one (mDNS's own timing belongs to the live-run gate, and
//! its per-node feed is pinned by the paused-clock tests in `bifrost-mdns`). It holds one state per
//! test, conflates like a real source, counts the reads its subscribers make, and flags the moment
//! a subscription is dropped: the abort guard every cancellation claim here is checked against.
//!
//! The properties: a node heard after the dial began is what the transport dials; a hinted dial
//! never waits on a silent source; no update ever causes a dial, and the subscription dies with the
//! attempt so no later update has anyone to act on it; dropping a dial cancels its subscription;
//! and a transport that finds peers itself never waits on the feed at all.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use bifrost::{
    Addr, AddrUpdate, Announced, Discovery, Error, HintStream, Latest, Layered, Node, NodeId,
    Session, StaticDiscovery, Transport,
};
use bifrost_mem::MemTransport;
use futures_util::stream;
use tokio::sync::watch;
use tokio::{io, time};

/// The dial begins before the source has heard the peer; the source hears it mid-dial, and that
/// record is what the transport dials. This is the case a bounded wait used to exist for.
#[tokio::test(start_paused = true)]
async fn a_node_heard_after_the_dial_began_is_dialed() {
    let peer = id(0x11);
    let source = Scripted::default();
    let transport = Recording::default();
    let log = transport.log.clone();
    let node = Node::new(
        transport,
        Layered::new(StaticDiscovery::new(), source.clone()),
    );

    let (dialed, ()) = tokio::join!(node.connect(peer), async {
        time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            log.dials(),
            0,
            "nothing is dialed before the source answers"
        );
        source.say(AddrUpdate::Hints(vec![addr(7001)]));
    });

    dialed.expect("the dial reaches the peer once the source hears it");
    assert_eq!(log.hints(), vec![addr(7001)]);
    assert_eq!(log.dials(), 1);
}

/// A hinted dial goes at once: a hand-fed hint answers the union, so a learned source that has not
/// spoken costs nothing, and its subscription is dropped with the finished attempt.
#[tokio::test(start_paused = true)]
async fn a_hinted_dial_never_waits_for_a_silent_source() {
    let peer = id(0x22);
    let mut hints = StaticDiscovery::new();
    hints.insert(peer, vec![addr(7002)]);
    let silent = Scripted::default();
    let transport = Recording::default();
    let log = transport.log.clone();
    let node = Node::new(transport, Layered::new(hints, silent.clone()));

    let started = time::Instant::now();
    // Bounded, so a union that waits on the silent source fails here instead of hanging the suite.
    time::timeout(Duration::from_secs(5), node.connect(peer))
        .await
        .expect("a hinted dial must not wait on a silent source")
        .expect("a hinted dial reaches the peer at once");

    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "a hinted dial pays no wait"
    );
    assert_eq!(log.hints(), vec![addr(7002)]);
    assert_eq!(
        silent.live(),
        0,
        "the silent source's subscription must be dropped with the attempt"
    );
}

/// No discovery update causes a dial. With no dial in flight nothing is subscribed, so an update
/// has no one to reach; during a dial, only the first observation is read; after it, the
/// subscription is gone, so later hints and a removal have no consumer to act on them. One caller
/// dial is one transport dial.
#[tokio::test(start_paused = true)]
async fn no_discovery_update_causes_a_dial() {
    let peer = id(0x33);
    let source = Scripted::default();
    let transport = Recording::default();
    let log = transport.log.clone();
    let node = Node::new(transport, source.clone());

    for port in 1..=50 {
        source.say(AddrUpdate::Hints(vec![addr(port)]));
        time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        source.live(),
        0,
        "with no dial in flight nothing may be subscribed, so no update has anyone to act on it"
    );

    source.say(AddrUpdate::Removed);
    let (dialed, ()) = tokio::join!(node.connect(peer), async {
        time::sleep(Duration::from_millis(10)).await;
        source.say(AddrUpdate::Hints(vec![addr(7003)]));
        for update in [
            AddrUpdate::Hints(vec![addr(7004)]),
            AddrUpdate::Removed,
            AddrUpdate::Hints(vec![addr(7005)]),
        ] {
            time::sleep(Duration::from_millis(10)).await;
            source.say(update);
        }
        time::sleep(Duration::from_millis(10)).await;
        source.end();
    });

    dialed.expect("the caller's one dial succeeds");
    assert_eq!(
        log.dials(),
        1,
        "a discovery update must never cause a dial: one caller dial, one transport dial"
    );
    assert_eq!(
        log.hints(),
        vec![addr(7003)],
        "the dial used the first observation"
    );
    assert_eq!(
        source.live(),
        0,
        "the subscription must be dropped when the attempt ends"
    );
}

/// Dropping a dial that is waiting on a silent source drops its subscription: the caller's deadline
/// is the only bound, and when it fires the source is told to stop.
#[tokio::test(start_paused = true)]
async fn dropping_the_dial_cancels_its_subscription() {
    let silent = Scripted::default();
    let node = Node::new(Recording::default(), silent.clone());

    let outcome = time::timeout(Duration::from_secs(5), node.connect(id(0x44))).await;

    assert!(
        outcome.is_err(),
        "a silent source holds the dial until the caller's deadline"
    );
    assert!(silent.reads() > 0, "the dial did read the feed");
    assert_eq!(
        silent.live(),
        0,
        "the caller's deadline must drop the subscription"
    );
}

/// A transport that finds peers itself dials without waiting on the feed, even one that never
/// answers: mem's registry is its discovery, and the feed is not read at all.
#[tokio::test(start_paused = true)]
async fn a_self_discovering_transport_never_waits_on_the_feed() {
    let receiver = MemTransport::bind();
    let silent = Scripted::default();
    let sender = Node::new(MemTransport::bind(), silent.clone());

    let started = time::Instant::now();
    let dialed = time::timeout(Duration::from_secs(5), sender.connect(receiver.node_id())).await;

    assert!(
        matches!(dialed, Ok(Ok(_))),
        "mem dials at once over a silent feed"
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(
        silent.reads(),
        0,
        "a self-discovering dial never reads the feed"
    );
}

/// A source the test drives. It holds one state for its node and every subscription re-reads it on
/// wake, so a slow subscriber sees the latest state (as a real source must), never a queue.
#[derive(Clone, Default)]
struct Scripted(Arc<Script>);

struct Script {
    /// `None` until the test says something.
    state: watch::Sender<Option<AddrUpdate>>,
    /// Set once the test ends the source: every feed ends after its next read.
    ended: watch::Sender<bool>,
    /// How many times a subscriber read the state.
    reads: AtomicUsize,
    /// Subscriptions not yet dropped.
    live: AtomicUsize,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            state: watch::channel(None).0,
            ended: watch::channel(false).0,
            reads: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
        }
    }
}

impl Scripted {
    fn say(&self, update: AddrUpdate) {
        self.0.state.send_replace(Some(update));
    }

    fn end(&self) {
        self.0.ended.send_replace(true);
    }

    fn reads(&self) -> usize {
        self.0.reads.load(Ordering::SeqCst)
    }

    fn live(&self) -> usize {
        self.0.live.load(Ordering::SeqCst)
    }
}

impl Discovery for Scripted {
    fn subscribe(&self, _node: NodeId) -> HintStream {
        self.0.live.fetch_add(1, Ordering::SeqCst);
        let feed = Feed {
            state: self.0.state.subscribe(),
            ended: self.0.ended.subscribe(),
            said: Latest::default(),
            guard: Guard(Arc::clone(&self.0)),
        };
        HintStream::new(stream::unfold(feed, |mut feed| async move {
            let update = feed.next().await?;
            Some((Ok(update), feed))
        }))
    }
}

/// One subscription to a [`Scripted`] source.
struct Feed {
    state: watch::Receiver<Option<AddrUpdate>>,
    ended: watch::Receiver<bool>,
    said: Latest,
    guard: Guard,
}

impl Feed {
    async fn next(&mut self) -> Option<AddrUpdate> {
        loop {
            self.guard.0.reads.fetch_add(1, Ordering::SeqCst);
            if *self.ended.borrow_and_update() {
                return None;
            }
            let (hints, settled) = match self.state.borrow_and_update().clone() {
                Some(AddrUpdate::Hints(hints)) => (hints, false),
                Some(AddrUpdate::Settled) => (Vec::new(), true),
                Some(AddrUpdate::Removed) | None => (Vec::new(), false),
            };
            if let Some(update) = self.said.say(hints, settled) {
                return Some(update);
            }
            tokio::select! {
                changed = self.state.changed() => changed.ok()?,
                changed = self.ended.changed() => changed.ok()?,
            }
        }
    }
}

/// The abort guard: counts a subscription out when it is dropped, however the drop came about.
struct Guard(Arc<Script>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a [`Recording`] transport was asked to do, shared with the test after the transport moves
/// into the node.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Calls>>);

#[derive(Default)]
struct Calls {
    dials: Vec<Addr>,
}

impl Log {
    fn calls(&self) -> std::sync::MutexGuard<'_, Calls> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn dials(&self) -> usize {
        self.calls().dials.len()
    }

    fn hints(&self) -> Vec<SocketAddr> {
        self.calls()
            .dials
            .last()
            .map(|addr| addr.hints.clone())
            .unwrap_or_default()
    }
}

/// A direct-only transport that records every dial and refuses a hint-less one, so a dial that
/// went before discovery answered fails instead of passing. It inherits the default
/// `connect_with_updates`, which is what the dial path under test is.
#[derive(Default)]
struct Recording {
    log: Log,
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

impl Transport for Recording {
    type Security = Announced;
    type Session = Recorded;

    fn node_id(&self) -> NodeId {
        id(0x99)
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(self.node_id())
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    async fn connect(&self, addr: Addr) -> Result<Recorded, Error> {
        if addr.hints.is_empty() {
            return Err(Error::Connect(Box::new(NoHints)));
        }
        let peer = addr.node;
        self.log.calls().dials.push(addr);
        Ok(Recorded { peer })
    }

    async fn accept(&self) -> Result<Recorded, Error> {
        Ok(Recorded {
            peer: self.node_id(),
        })
    }

    async fn close(&self) {}
}

/// A session that carries only the dialed identity; these tests never open a stream.
struct Recorded {
    peer: NodeId,
}

impl Session for Recorded {
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

    /// A double that carries no streams has nothing to end.
    fn close(&self) {}
}

/// A distinct ed25519 [`NodeId`] seeded by one byte, enough to tell test identities apart.
fn id(seed: u8) -> NodeId {
    NodeId::from_ed25519_secret(&[seed; NodeId::KEY_LEN])
}

/// A loopback socket address on the given port.
fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
