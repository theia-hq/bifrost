//! The discovery vocabulary polled by hand: the fixed sources, and the union `Layered` merges.
//!
//! Every feed here is polled with a no-op waker, so each test states exactly what a subscriber
//! sees at each step with no runtime and no timing in the loop. The scripted source is deliberately
//! a QUEUE (every push is a separate item) so the union's own conflation is what the burst test
//! observes, not a property borrowed from the double.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::task::Wake;

use futures_core::Stream;

use crate::{
    AddrUpdate, Discovery, Error, HintStream, Layered, NoDiscovery, NodeId, StaticDiscovery,
};

/// A fixed table answers with its entry once and ends; there is never anything more to say.
#[test]
fn a_static_entry_answers_once_then_ends() {
    let mut table = StaticDiscovery::new();
    table.insert(peer(), vec![addr(1)]);
    let mut feed = table.subscribe(peer());

    assert_eq!(poll(&mut feed), said(AddrUpdate::Hints(vec![addr(1)])));
    assert_eq!(poll(&mut feed), Poll::Ready(None));
}

/// A fixed table with no entry (or an empty one) settles at once: it is ready by construction.
#[test]
fn a_static_miss_settles_then_ends() {
    let mut table = StaticDiscovery::new();
    table.insert(other(), Vec::new());

    for node in [peer(), other()] {
        let mut feed = table.subscribe(node);
        assert_eq!(poll(&mut feed), said(AddrUpdate::Settled));
        assert_eq!(poll(&mut feed), Poll::Ready(None));
    }
}

/// `NoDiscovery` has nothing and never will: its feed has already ended.
#[test]
fn no_discovery_has_already_ended() {
    assert_eq!(poll(&mut NoDiscovery.subscribe(peer())), Poll::Ready(None));
    assert_eq!(
        poll(&mut Layered::new(NoDiscovery, NoDiscovery).subscribe(peer())),
        Poll::Ready(None)
    );
}

/// The union leads with the primary's hints and drops the secondary's duplicates.
#[test]
fn the_union_leads_with_the_primary_and_drops_duplicates() {
    let mut primary = StaticDiscovery::new();
    primary.insert(peer(), vec![addr(1), addr(2)]);
    let (secondary, script) = Scripted::new();
    script.push(AddrUpdate::Hints(vec![addr(2), addr(3)]));

    let mut feed = Layered::new(primary, secondary).subscribe(peer());

    assert_eq!(
        poll(&mut feed),
        said(AddrUpdate::Hints(vec![addr(1), addr(2), addr(3)]))
    );
}

/// A fixed table that settles at once does not cut short a learned source that is still looking:
/// the union holds its first answer until every source has answered.
#[test]
fn the_union_holds_its_first_answer_until_every_source_answers() {
    let (secondary, script) = Scripted::new();
    let mut feed = Layered::new(StaticDiscovery::new(), secondary).subscribe(peer());

    assert_eq!(
        poll(&mut feed),
        Poll::Pending,
        "a static miss must not settle the union while the learned source is still looking"
    );

    script.push(AddrUpdate::Settled);
    assert_eq!(poll(&mut feed), said(AddrUpdate::Settled));
    assert_eq!(poll(&mut feed), Poll::Pending, "settled is said once");
}

/// One source's hit answers at once, without waiting for a source that has not spoken.
#[test]
fn a_hit_answers_before_a_silent_source_speaks() {
    let mut primary = StaticDiscovery::new();
    primary.insert(peer(), vec![addr(1)]);
    let (secondary, _script) = Scripted::new();

    let mut feed = Layered::new(primary, secondary).subscribe(peer());

    assert_eq!(poll(&mut feed), said(AddrUpdate::Hints(vec![addr(1)])));
}

/// A node heard after the subscription settled still reaches the subscriber: settled is not final
/// for a source that keeps watching.
#[test]
fn a_node_heard_after_settling_reaches_the_subscriber() {
    let (secondary, script) = Scripted::new();
    let mut feed = Layered::new(StaticDiscovery::new(), secondary).subscribe(peer());
    script.push(AddrUpdate::Settled);
    assert_eq!(poll(&mut feed), said(AddrUpdate::Settled));

    script.push(AddrUpdate::Hints(vec![addr(4)]));
    assert_eq!(poll(&mut feed), said(AddrUpdate::Hints(vec![addr(4)])));
}

/// A removal from the learned source withdraws only that source's hints: the address the user
/// supplied survives it, so a forged LAN expiry cannot erase a static hint.
#[test]
fn a_removal_withdraws_only_its_own_source() {
    let mut primary = StaticDiscovery::new();
    primary.insert(peer(), vec![addr(1)]);
    let (secondary, script) = Scripted::new();
    script.push(AddrUpdate::Hints(vec![addr(2)]));
    let mut feed = Layered::new(primary, secondary).subscribe(peer());
    assert_eq!(
        poll(&mut feed),
        said(AddrUpdate::Hints(vec![addr(1), addr(2)]))
    );

    script.push(AddrUpdate::Removed);
    assert_eq!(
        poll(&mut feed),
        said(AddrUpdate::Hints(vec![addr(1)])),
        "the static hint must survive the learned source's removal"
    );
}

/// When every source has withdrawn, the union says `Removed`, and says it once.
#[test]
fn the_union_says_removed_when_every_source_withdraws() {
    let (primary, first) = Scripted::new();
    let (secondary, second) = Scripted::new();
    first.push(AddrUpdate::Hints(vec![addr(1)]));
    second.push(AddrUpdate::Hints(vec![addr(2)]));
    let mut feed = Layered::new(primary, secondary).subscribe(peer());
    assert_eq!(
        poll(&mut feed),
        said(AddrUpdate::Hints(vec![addr(1), addr(2)]))
    );

    first.push(AddrUpdate::Removed);
    second.push(AddrUpdate::Removed);
    assert_eq!(poll(&mut feed), said(AddrUpdate::Removed));
    assert_eq!(poll(&mut feed), Poll::Pending);
}

/// A slow subscriber sees the latest union, never a backlog. The source here queues every push, so
/// this fails the moment the union forwards items one at a time instead of draining to the latest.
#[test]
fn a_burst_conflates_to_the_latest_union() {
    let (secondary, script) = Scripted::new();
    let mut feed = Layered::new(StaticDiscovery::new(), secondary).subscribe(peer());
    for port in 1..=100 {
        script.push(AddrUpdate::Hints(vec![addr(port)]));
    }

    assert_eq!(
        poll(&mut feed),
        said(AddrUpdate::Hints(vec![addr(100)])),
        "a slow subscriber must see the latest state, not the first of a backlog"
    );
    assert_eq!(
        poll(&mut feed),
        Poll::Pending,
        "nothing is queued behind the latest state"
    );
}

/// A source that ends keeps its last word in the union, and the union ends once every source has.
#[test]
fn an_ended_source_keeps_its_last_word() {
    let (secondary, script) = Scripted::new();
    script.push(AddrUpdate::Hints(vec![addr(5)]));
    let mut feed = Layered::new(NoDiscovery, secondary).subscribe(peer());
    assert_eq!(poll(&mut feed), said(AddrUpdate::Hints(vec![addr(5)])));

    script.end();
    assert_eq!(
        poll(&mut feed),
        Poll::Ready(None),
        "an end is not a removal: nothing more is said, and the union ends with its sources"
    );
}

/// One source failing does not fail the union: the other source still answers the dial.
#[test]
fn a_failed_source_does_not_fail_the_union() {
    let (primary, broken) = Scripted::new();
    let (secondary, working) = Scripted::new();
    broken.fail();
    working.push(AddrUpdate::Hints(vec![addr(6)]));

    let mut feed = Layered::new(primary, secondary).subscribe(peer());

    assert_eq!(poll(&mut feed), said(AddrUpdate::Hints(vec![addr(6)])));
}

/// A union whose every source failed, holding nothing, fails as a lone failed source would: the
/// dial gets the reason, not a bare attempt with none. Said once, then the feed ends.
#[test]
fn a_union_whose_every_source_failed_fails_the_dial() {
    let (primary, first) = Scripted::new();
    let (secondary, second) = Scripted::new();
    first.fail();
    second.fail();

    let mut feed = Layered::new(primary, secondary).subscribe(peer());

    assert_eq!(
        poll(&mut feed),
        Poll::Ready(Some(Err("connect to peer".to_owned()))),
        "a union with no source left and nothing held must surface why"
    );
    assert_eq!(
        poll(&mut feed),
        Poll::Ready(None),
        "the failure is said once"
    );
}

/// A failure beside a source that is still looking stays silent: the live source's answer is the
/// union's answer, here that it has settled.
#[test]
fn a_failed_source_beside_a_settled_one_does_not_fail() {
    let (primary, broken) = Scripted::new();
    let (secondary, working) = Scripted::new();
    broken.fail();
    working.push(AddrUpdate::Settled);

    let mut feed = Layered::new(primary, secondary).subscribe(peer());

    assert_eq!(poll(&mut feed), said(AddrUpdate::Settled));
    assert_eq!(poll(&mut feed), Poll::Pending);
}

/// A source that is ready on every poll cannot hold the thread: the union takes a bounded share,
/// says nothing it may already know is stale, and wakes itself to be polled again.
#[test]
fn a_source_that_never_pends_cannot_hold_the_thread() {
    let endless = Endless::default();
    let mut feed = Layered::new(NoDiscovery, endless.clone()).subscribe(peer());
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));

    let first = Pin::new(&mut feed).poll_next(&mut Context::from_waker(&waker));

    assert!(
        endless.polls() < Endless::LIMIT,
        "one poll must take a bounded share of an endless source, took {}",
        endless.polls()
    );
    assert!(
        first.is_pending(),
        "nothing is said while a source is still yielding"
    );
    assert_eq!(wakes.count(), 1, "the union asks to be polled again");
}

/// Dropping the merged feed drops both subscriptions under it, which is each source's stop signal.
#[test]
fn dropping_the_union_drops_both_subscriptions() {
    let (primary, first) = Scripted::new();
    let (secondary, second) = Scripted::new();
    let mut feed = Layered::new(primary, secondary).subscribe(peer());
    assert_eq!(poll(&mut feed), Poll::Pending);
    assert!(!first.dropped() && !second.dropped());

    drop(feed);

    assert!(
        first.dropped(),
        "the primary's subscription must be dropped"
    );
    assert!(
        second.dropped(),
        "the secondary's subscription must be dropped"
    );
}

/// A source whose feed is a queue the test pushes into, one subscription at a time.
struct Scripted(Script);

impl Scripted {
    fn new() -> (Self, Script) {
        let script = Script(Arc::new(Mutex::new(State::default())));
        (Self(script.clone()), script)
    }
}

impl Discovery for Scripted {
    fn subscribe(&self, _node: NodeId) -> HintStream {
        HintStream::new(Subscription(self.0.clone()))
    }
}

/// The test's handle on a scripted source.
#[derive(Clone)]
struct Script(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    queue: VecDeque<Result<AddrUpdate, Error>>,
    ended: bool,
    dropped: bool,
}

impl Script {
    fn push(&self, update: AddrUpdate) {
        self.state().queue.push_back(Ok(update));
    }

    fn fail(&self) {
        self.state()
            .queue
            .push_back(Err(Error::Connect(Box::new(io::Error::other(
                "source down",
            )))));
    }

    fn end(&self) {
        self.state().ended = true;
    }

    fn dropped(&self) -> bool {
        self.state().dropped
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct Subscription(Script);

impl Stream for Subscription {
    type Item = Result<AddrUpdate, Error>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self.0.state();
        match state.queue.pop_front() {
            Some(item) => Poll::Ready(Some(item)),
            None if state.ended => Poll::Ready(None),
            None => Poll::Pending,
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.0.state().dropped = true;
    }
}

/// A source that is ready on every poll with the same state, never `Pending`. It ends after
/// [`LIMIT`](Self::LIMIT) items only so an unbounded drain shows up as a count, not a hang.
#[derive(Clone, Default)]
struct Endless(Arc<AtomicUsize>);

impl Endless {
    const LIMIT: usize = 100_000;

    fn polls(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Discovery for Endless {
    fn subscribe(&self, _node: NodeId) -> HintStream {
        HintStream::new(self.clone())
    }
}

impl Stream for Endless {
    type Item = Result<AddrUpdate, Error>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polls = self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Ready((polls < Self::LIMIT).then(|| Ok(AddrUpdate::Hints(vec![addr(1)]))))
    }
}

/// A waker that counts how often it is woken.
#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wakes {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// One poll of a feed, reduced to what a subscriber can compare (the error itself is not `Eq`).
fn poll(feed: &mut HintStream) -> Poll<Option<Result<AddrUpdate, String>>> {
    Pin::new(feed)
        .poll_next(&mut Context::from_waker(Waker::noop()))
        .map(|item| item.map(|update| update.map_err(|err| err.to_string())))
}

fn said(update: AddrUpdate) -> Poll<Option<Result<AddrUpdate, String>>> {
    Poll::Ready(Some(Ok(update)))
}

fn peer() -> NodeId {
    NodeId::from_ed25519_secret(&[0x11; NodeId::KEY_LEN])
}

fn other() -> NodeId {
    NodeId::from_ed25519_secret(&[0x22; NodeId::KEY_LEN])
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
