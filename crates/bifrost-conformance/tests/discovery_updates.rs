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
//!
//! A dial's own hints (`connect_hinted`): with none it hands the transport what `connect` does; its
//! hints lead the feed as given, repeats and all, then what discovery finds; they are in the feed's
//! first answer before any source speaks; and they reach only the dial they were given to.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use bifrost::{
    Addr, AddrUpdate, Discovery, Error, HintStream, Latest, Layered, Node, NodeId, Path,
    PathChanges, Session, StaticDiscovery, Transport,
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

/// With no hints of its own, a hinted dial is a plain one: the transport gets the same first answer.
#[tokio::test(start_paused = true)]
async fn connect_hinted_with_no_hints_is_connect() {
    let peer = id(0x55);
    let transport = Recording::default();
    let log = transport.log.clone();
    let node = Node::new(transport, table(peer, vec![addr(7006)]));

    node.connect(peer).await.expect("a plain dial goes");
    node.connect_hinted(peer, &[])
        .await
        .expect("a hinted dial with no hints goes");

    assert_eq!(log.each(), vec![vec![addr(7006)], vec![addr(7006)]]);
}

/// The call's hints lead, exactly as given, and what discovery finds follows them.
#[tokio::test(start_paused = true)]
async fn connect_hinted_leads_with_the_calls_hints_as_given() {
    let peer = id(0x66);
    let transport = Recording::default();
    let log = transport.log.clone();
    let node = Node::new(transport, table(peer, vec![addr(7007)]));

    node.connect_hinted(peer, &[addr(7008), addr(7008), addr(7007)])
        .await
        .expect("a hinted dial goes");

    assert_eq!(
        log.hints(),
        vec![addr(7008), addr(7008), addr(7007)],
        "the call's hints reach the transport in order, repeats kept, ahead of discovery's"
    );
}

/// A transport that reads only what the feed holds at the instant it dials still gets the call's
/// hints, over a source that never answers.
#[tokio::test(start_paused = true)]
async fn connect_hinted_hints_are_ready_at_once() {
    let silent = Scripted::default();
    let transport = Glancing(Recording::default());
    let log = transport.0.log.clone();
    let node = Node::new(transport, silent.clone());

    node.connect_hinted(id(0x77), &[addr(7009)])
        .await
        .expect("the hints are there at once");

    assert_eq!(log.hints(), vec![addr(7009)]);
    assert!(silent.reads() > 0, "the silent source was subscribed");
}

/// Two dials to one peer through one node: the hinted one is parked in the transport while a
/// plain one runs from start to finish, and the plain one never sees the other's hint.
#[tokio::test(start_paused = true)]
async fn connect_hinted_hints_stay_in_their_own_feed() {
    let peer = id(0x88);
    let (release, parked) = watch::channel(false);
    let transport = Recording {
        park: Some((addr(7010), parked)),
        ..Recording::default()
    };
    let log = transport.log.clone();
    let node = Node::new(transport, table(peer, vec![addr(7011)]));

    let hints = [addr(7010)];
    let (hinted, ()) = tokio::join!(node.connect_hinted(peer, &hints), async {
        // The barrier: the hinted dial has reached the transport and is parked there. Bounded, so
        // a hinted dial refused before it reaches the transport fails here instead of hanging.
        time::timeout(Duration::from_secs(5), log.dialed(1))
            .await
            .expect("the hinted dial reaches the transport");
        // Bounded, since a plain dial that picked up the hint would park beside it for ever.
        time::timeout(Duration::from_secs(5), node.connect(peer))
            .await
            .expect("a plain dial carrying the other dial's hint was parked with it")
            .expect("the plain dial goes while the hinted one is parked");
        assert_eq!(
            log.each(),
            vec![vec![addr(7010), addr(7011)], vec![addr(7011)]],
            "the plain dial carries only what discovery finds"
        );
        release.send_replace(true);
    });

    hinted.expect("the parked dial goes once released");
}

/// A fixed table holding `hints` for `peer`.
fn table(peer: NodeId, hints: Vec<SocketAddr>) -> StaticDiscovery {
    let mut table = StaticDiscovery::new();
    table.insert(peer, hints);
    table
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
#[derive(Clone)]
struct Log {
    calls: Arc<Mutex<Calls>>,
    /// How many dials have been recorded, so a test can wait on one reaching the transport.
    count: watch::Sender<usize>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            calls: Arc::default(),
            count: watch::channel(0).0,
        }
    }
}

#[derive(Default)]
struct Calls {
    dials: Vec<Addr>,
}

impl Log {
    fn calls(&self) -> std::sync::MutexGuard<'_, Calls> {
        self.calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn record(&self, addr: Addr) {
        let dials = {
            let mut calls = self.calls();
            calls.dials.push(addr);
            calls.dials.len()
        };
        self.count.send_replace(dials);
    }

    /// Wait until at least `dials` dials have been recorded.
    async fn dialed(&self, dials: usize) {
        let mut count = self.count.subscribe();
        // The sender lives in this log, so the channel cannot close while it is awaited.
        let _ = count.wait_for(|recorded| *recorded >= dials).await;
    }

    fn dials(&self) -> usize {
        self.calls().dials.len()
    }

    /// Every dial's hints, in the order the dials reached the transport.
    fn each(&self) -> Vec<Vec<SocketAddr>> {
        self.calls()
            .dials
            .iter()
            .map(|addr| addr.hints.clone())
            .collect()
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
    /// A dial carrying this address is recorded and then held until the receiver reads `true`, so
    /// a test can keep one dial in flight while another runs.
    park: Option<(SocketAddr, watch::Receiver<bool>)>,
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
        let parks = self
            .park
            .as_ref()
            .filter(|(parked, _)| addr.hints.contains(parked))
            .map(|(_, release)| release.clone());
        self.log.record(addr);
        if let Some(mut release) = parks {
            // The test holds the sender until it releases, so a closed channel is a test bug.
            let _ = release.wait_for(|go| *go).await;
        }
        Ok(Recorded { peer })
    }

    async fn accept(&self) -> Result<Recorded, Error> {
        Ok(Recorded {
            peer: self.node_id(),
        })
    }

    async fn close(&self) {}
}

/// A [`Recording`] that never waits on its feed: it dials with what the feed holds at that instant,
/// the way a transport that finds peers by key reads it.
struct Glancing(Recording);

impl Transport for Glancing {
    type Session = Recorded;

    fn node_id(&self) -> NodeId {
        self.0.node_id()
    }

    fn local_addr(&self) -> Addr {
        self.0.local_addr()
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.0.bound_sockets()
    }

    async fn connect(&self, addr: Addr) -> Result<Recorded, Error> {
        self.0.connect(addr).await
    }

    async fn connect_with_updates(
        &self,
        addr: Addr,
        updates: HintStream,
    ) -> Result<Recorded, Error> {
        self.0.connect(addr.seeded(updates.ready())?).await
    }

    async fn accept(&self) -> Result<Recorded, Error> {
        self.0.accept().await
    }

    async fn close(&self) {
        self.0.close().await;
    }
}

/// A session that carries only the dialed identity; these tests never open a stream.
struct Recorded {
    peer: NodeId,
}

impl Session for Recorded {
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

    fn path_changes(&self) -> PathChanges {
        PathChanges::fixed(Path::Unknown)
    }
}

/// A distinct ed25519 [`NodeId`] seeded by one byte, enough to tell test identities apart.
fn id(seed: u8) -> NodeId {
    NodeId::from_ed25519_secret(&[seed; NodeId::KEY_LEN])
}

/// A loopback socket address on the given port.
fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
