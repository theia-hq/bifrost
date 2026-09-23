//! In-process mDNS behavior: two [`MdnsDiscovery`] instances advertise and hear each other, plus
//! deterministic subscription tests that write through the private table the browse writes.
//!
//! The multicast tests drive real sockets over the loopback/default interface, so they are
//! `#[ignore]`d by default: CI and sandboxed environments routinely block multicast, and a
//! network-dependent test must not flake the suite. Run them locally with
//! `cargo test -p bifrost-mdns -- --ignored` to exercise the full advertise + browse + subscribe path
//! against the OS mDNS stack. The subscription tests use the paused clock and write the table
//! directly through the same calls the browse callback makes, so they run everywhere with no network.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Waker};
use core::time::Duration;
use std::sync::Arc;
use std::task::Wake;

use bifrost_core::{AddrUpdate, CryptoKind, Discovery, HintStream, NodeId};
use futures_util::{Stream, StreamExt as _};
use tokio::time::{self, Instant};

use super::{Heard, MAX_HINTS, MdnsDiscovery, SETTLE_WINDOW, shape};

/// Two nodes advertising on the LAN hear each other's advertised address over mDNS.
#[tokio::test]
#[ignore = "drives real multicast; run locally with --ignored"]
async fn two_nodes_hear_each_other_over_mdns() {
    let (alice, alice_addr) = (node(1), addr(4001));
    let (bob, bob_addr) = (node(2), addr(4002));

    // Hold both guards for the whole test: dropping one stops its advertisement.
    let alice_mdns = MdnsDiscovery::advertise(alice, [alice_addr])
        .expect("alice advertises")
        .discovery;
    let bob_mdns = MdnsDiscovery::advertise(bob, [bob_addr])
        .expect("bob advertises")
        .discovery;

    // Each hears the OTHER: alice learns bob's addr, bob learns alice's, both from the network.
    let found_bob = hints_within(&alice_mdns, bob, Duration::from_secs(10)).await;
    let found_alice = hints_within(&bob_mdns, alice, Duration::from_secs(10)).await;

    assert!(
        found_bob.contains(&bob_addr),
        "alice should hear bob's advertised addr, got {found_bob:?}"
    );
    assert!(
        found_alice.contains(&alice_addr),
        "bob should hear alice's advertised addr, got {found_alice:?}"
    );
}

/// A peer nobody advertises settles after the window: an answer, not a hang and not an error, so a
/// layered caller falls through gracefully.
#[tokio::test]
#[ignore = "drives real multicast; run locally with --ignored"]
async fn an_unheard_peer_settles_over_mdns() {
    let mdns = MdnsDiscovery::advertise(node(3), [addr(4003)])
        .expect("advertises")
        .discovery;
    let first = time::timeout(Duration::from_secs(10), mdns.subscribe(node(99)).first())
        .await
        .expect("an unheard peer is answered within the window");
    assert!(
        matches!(first, Some(Ok(AddrUpdate::Settled))),
        "an unheard peer settles, got {first:?}"
    );
}

/// A subscription releases on the TARGET over real multicast. A fresh browser hears its own
/// advertisement echoed back first, which must not release a subscription for the peer; once the
/// peer's record lands the feed answers with it.
#[tokio::test]
#[ignore = "drives real multicast; run locally with --ignored"]
async fn a_subscription_releases_on_the_target_over_mdns() {
    let alice = node(51);
    let bob = node(52);
    let bob_addr = addr(4052);

    let alice_mdns = MdnsDiscovery::advertise(alice, [addr(4051)])
        .expect("alice advertises")
        .discovery;
    let bob_mdns = MdnsDiscovery::advertise(bob, [bob_addr])
        .expect("bob advertises")
        .discovery;

    let first = time::timeout(Duration::from_secs(10), alice_mdns.subscribe(bob).first())
        .await
        .expect("bob is heard within the window");
    assert!(
        matches!(&first, Some(Ok(AddrUpdate::Hints(hints))) if hints.contains(&bob_addr)),
        "alice's first word on bob is bob's address, got {first:?}"
    );
    drop(bob_mdns);
}

/// The case a subscription exists for: a node heard AFTER the subscriber asked still reaches it,
/// as soon as it is heard and not at the end of the window. The paused clock proves the answer came
/// from the record, since the settle window has not elapsed when it arrives.
#[tokio::test(start_paused = true)]
async fn a_node_heard_after_subscribing_reaches_the_subscriber() {
    let (mdns, heard) = fresh();
    let target = node(40);
    let mut feed = mdns.subscribe(target);
    assert!(
        quiet_for(&mut feed, Duration::from_millis(100)).await,
        "nothing is said before the target is heard or the window passes"
    );

    let asked = Instant::now();
    heard.learn(target, vec![addr(4040)]);

    assert_eq!(
        feed.next().await.and_then(Result::ok),
        Some(AddrUpdate::Hints(vec![addr(4040)])),
        "the target's record must reach a subscription made before it was heard"
    );
    assert_eq!(
        asked.elapsed(),
        Duration::ZERO,
        "the record answers at once, not when the window's timer next re-reads the table"
    );
}

/// An observation of another peer (the dialing node's own advertisement echoed back by multicast
/// loopback) says nothing on the target's feed; only the target's own record does.
#[tokio::test(start_paused = true)]
async fn a_self_observation_does_not_release_the_target() {
    let (mdns, heard) = fresh();
    let target = node(41);
    let mut feed = mdns.subscribe(target);

    heard.learn(node(1), vec![addr(4001)]);
    assert!(
        quiet_for(&mut feed, Duration::from_millis(100)).await,
        "another peer's record must not release the target's feed"
    );

    heard.learn(target, vec![addr(4041)]);
    assert_eq!(
        feed.next().await.and_then(Result::ok),
        Some(AddrUpdate::Hints(vec![addr(4041)]))
    );
}

/// Wakeups are per node: a flood of records for other peers never wakes the target's subscriber,
/// so N waiting dials cost nothing per unrelated packet. The counting waker sees every wake the
/// feed's poll registered.
#[tokio::test(start_paused = true)]
async fn records_for_other_nodes_never_wake_the_subscriber() {
    let (mdns, heard) = fresh();
    let target = node(42);
    let mut feed = mdns.subscribe(target);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));

    assert!(
        Pin::new(&mut feed)
            .poll_next(&mut Context::from_waker(&waker))
            .is_pending()
    );
    for seed in 100..200 {
        heard.learn(node(seed), vec![addr(u16::from(seed))]);
    }
    assert_eq!(
        wakes.count(),
        0,
        "records for other nodes must not wake this subscriber"
    );

    heard.learn(target, vec![addr(4042)]);
    assert_eq!(wakes.count(), 1, "the target's own record wakes it");
}

/// A node never heard settles once the window from the start of the service has passed, says so
/// exactly once, and keeps watching.
#[tokio::test(start_paused = true)]
async fn an_unheard_node_settles_once_when_the_window_passes() {
    let (mdns, _heard) = fresh();
    let started = Instant::now();
    let mut feed = mdns.subscribe(node(43));

    // Bounded, so a window that never passes fails here instead of hanging the suite.
    let first = time::timeout(SETTLE_WINDOW * 4, feed.next()).await;
    assert_eq!(
        first.ok().flatten().and_then(Result::ok),
        Some(AddrUpdate::Settled),
        "an unheard node settles when the window passes"
    );
    assert!(
        started.elapsed() >= SETTLE_WINDOW,
        "a miss is not final before the window"
    );
    assert!(
        quiet_for(&mut feed, Duration::from_secs(60)).await,
        "settled is said once"
    );
}

/// A long-lived instance whose window passed long ago settles a miss at once: the cold-start cost
/// is paid once per service, never once per dial.
#[tokio::test(start_paused = true)]
async fn a_warm_instance_settles_a_miss_at_once() {
    let (mdns, _heard) = fresh();
    time::advance(SETTLE_WINDOW).await;

    let asked = Instant::now();
    let first = mdns.subscribe(node(44)).first().await;

    assert!(matches!(first, Some(Ok(AddrUpdate::Settled))));
    assert_eq!(asked.elapsed(), Duration::ZERO, "a warm miss costs nothing");
}

/// A slow subscriber sees the LATEST state for its node, never a backlog of every change between
/// two polls. Were the feed a queue, the first item here would be the first record, not the last.
#[tokio::test(start_paused = true)]
async fn a_slow_subscriber_gets_the_latest_state_not_a_backlog() {
    let (mdns, heard) = fresh();
    let target = node(45);
    let mut feed = mdns.subscribe(target);

    for port in 1..=1000 {
        heard.learn(target, vec![addr(port)]);
    }

    assert_eq!(
        feed.next().await.and_then(Result::ok),
        Some(AddrUpdate::Hints(vec![addr(1000)])),
        "a slow subscriber must see the latest state, not the first of a backlog"
    );
    assert!(
        quiet_for(&mut feed, Duration::from_millis(100)).await,
        "nothing is queued behind the latest state"
    );
}

/// An expiry after an answer says `Removed`; an expiry the subscriber never saw the start of says
/// nothing, so no one is told about the loss of something it was never told it had.
#[tokio::test(start_paused = true)]
async fn a_removal_is_said_only_after_hints() {
    let (mdns, heard) = fresh();
    let target = node(46);
    let mut told = mdns.subscribe(target);
    heard.learn(target, vec![addr(4046)]);
    assert_eq!(
        told.next().await.and_then(Result::ok),
        Some(AddrUpdate::Hints(vec![addr(4046)]))
    );

    let mut untold = mdns.subscribe(target);
    heard.forget(target);

    assert_eq!(
        told.next().await.and_then(Result::ok),
        Some(AddrUpdate::Removed)
    );
    assert_eq!(
        untold.next().await.and_then(Result::ok),
        Some(AddrUpdate::Settled),
        "a subscriber that never saw hints is not told they were removed"
    );
}

/// A disabled instance will never hear anything, so every feed has already ended.
#[tokio::test]
async fn a_disabled_instance_has_ended_every_feed() {
    assert!(
        MdnsDiscovery::disabled()
            .subscribe(node(47))
            .first()
            .await
            .is_none()
    );
}

/// Dropping the service ends every feed it made, whether the feed was still in its window or had
/// already answered: a source that will never say more ends rather than leaving a subscriber
/// pending.
#[tokio::test(start_paused = true)]
async fn dropping_the_service_ends_its_feeds() {
    let (mdns, heard) = fresh();
    let target = node(71);
    let mut waiting = mdns.subscribe(node(72));
    let mut answered = mdns.subscribe(target);
    heard.learn(target, vec![addr(7201)]);
    assert_eq!(
        answered.next().await.and_then(Result::ok),
        Some(AddrUpdate::Hints(vec![addr(7201)]))
    );

    drop(mdns);

    for feed in [&mut waiting, &mut answered] {
        assert!(
            matches!(
                time::timeout(SETTLE_WINDOW * 2, feed.next()).await,
                Ok(None)
            ),
            "a feed must end with the service that made it"
        );
    }
}

/// A dropped subscription releases its wake channel, so the map holds only live subscriptions and
/// dial churn cannot grow it.
#[tokio::test(start_paused = true)]
async fn dropped_subscriptions_release_their_wake_channels() {
    let (mdns, heard) = fresh();
    for seed in 60..70 {
        drop(mdns.subscribe(node(seed)));
    }
    let _live = mdns.subscribe(node(70));

    assert_eq!(heard.table().watchers.len(), 1);
}

/// A hint set is deduplicated, capped, and leads with an address a LAN peer can use: the peer's
/// own loopback address never takes the slot a single-hint transport dials.
#[test]
fn a_hint_set_is_capped_and_leads_with_a_routed_address() {
    let loopback = addr(1);
    let link = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 2);
    let lan = |octet: u8| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, octet)), 3);

    let short = shape([loopback, link, lan(1), lan(1)]);
    assert_eq!(short, vec![lan(1), link, loopback]);

    let long = shape([loopback, link].into_iter().chain((1..=20).map(lan)));
    assert_eq!(
        long.len(),
        MAX_HINTS,
        "a forged record cannot inflate a hint set"
    );
    assert!(
        long.iter().all(|hint| *hint != loopback && *hint != link),
        "routed addresses fill the cap before narrower ones"
    );
}

/// A live-shaped instance with no service behind it, started now: the table is the handle a test
/// writes through, exactly as the browse callback does.
fn fresh() -> (MdnsDiscovery, Arc<Heard>) {
    let heard = Arc::new(Heard::new(Instant::now() + SETTLE_WINDOW));
    let mdns = MdnsDiscovery {
        heard: Some(Arc::clone(&heard)),
        _service: None,
    };
    (mdns, heard)
}

/// Whether the feed says nothing (and does not end) for `span` of the paused clock.
async fn quiet_for(feed: &mut HintStream, span: Duration) -> bool {
    time::timeout(span, feed.next()).await.is_err()
}

/// Await the feed until it carries hints or the budget passes, returning the last hints it carried.
async fn hints_within(mdns: &MdnsDiscovery, node: NodeId, budget: Duration) -> Vec<SocketAddr> {
    let mut feed = mdns.subscribe(node);
    let deadline = Instant::now() + budget;
    while let Ok(Some(update)) = time::timeout_at(deadline, feed.next()).await {
        if let Ok(AddrUpdate::Hints(hints)) = update {
            return hints;
        }
    }
    Vec::new()
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
}

/// A distinct ed25519 [`NodeId`] seeded by a single byte, enough to tell two test nodes apart.
fn node(seed: u8) -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [seed; NodeId::KEY_LEN])
}

/// A loopback socket address on the given port.
fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
