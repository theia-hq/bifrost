//! In-process mDNS behavior: two [`MdnsDiscovery`] instances advertise and resolve each other, plus
//! deterministic readiness tests that inject observations through the private table and stream.
//!
//! The multicast tests drive real sockets over the loopback/default interface, so they are
//! `#[ignore]`d by default: CI and sandboxed environments routinely block multicast, and a
//! network-dependent test must not flake the suite. Run them locally with
//! `cargo test -p bifrost-mdns -- --ignored` to exercise the full advertise + browse + resolve path
//! against the OS mDNS stack. The readiness tests use the paused clock and inject directly, so they
//! run everywhere with no network.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bifrost_core::{CryptoKind, Discovery, NodeId};
use tokio::sync::watch;

use super::{Advertised, MdnsDiscovery, MdnsError};

/// A multi-port bind (iroh 1.2.0 binds a v4 and a v6 socket on different ephemeral ports) cannot be
/// advertised whole, so it advertises the port of the v4 socket: the address a peer dials. The v6
/// socket on another port is left out, never folded into a port that cannot carry it.
#[test]
fn a_multi_port_bind_advertises_the_v4_sockets_port() {
    let v4: SocketAddr = "127.0.0.1:51979".parse().expect("a valid v4 address");
    let v6: SocketAddr = "[::1]:51987".parse().expect("a valid v6 address");

    let advertised = Advertised::of([v4, v6]).expect("the v4 socket makes the bind advertisable");
    assert_eq!(advertised.port, 51979, "the chosen port is the v4 socket's");
    assert_eq!(
        advertised.addrs,
        vec![v4],
        "only the addresses on the chosen port are advertised"
    );

    // A v6 socket that SHARES the chosen port rides along: the advertisement is the whole port group,
    // not merely the v4 socket.
    let v6_twin: SocketAddr = "[::1]:51979".parse().expect("a valid v6 address");
    let advertised =
        Advertised::of([v4, v6, v6_twin]).expect("the shared v4 port makes the bind advertisable");
    assert_eq!(advertised.port, 51979);
    assert_eq!(advertised.addrs, vec![v4, v6_twin]);
}

/// The single-port path is unchanged: one listener across interfaces is one port plus every bound
/// address, whatever family, and the multi-port preference never narrows it.
#[test]
fn a_single_port_bind_advertises_every_address() {
    let v4: SocketAddr = "127.0.0.1:51979".parse().expect("a valid v4 address");
    let v6: SocketAddr = "[::1]:51979".parse().expect("a valid v6 address");

    let advertised = Advertised::of([v4, v6]).expect("a shared port is advertisable");
    assert_eq!(advertised.port, 51979);
    assert_eq!(advertised.addrs, vec![v4, v6]);

    // A v6-only single-port bind keeps its prior behavior too.
    let advertised = Advertised::of([v6]).expect("a single v6 port is advertisable");
    assert_eq!(advertised.port, 51979);
    assert_eq!(advertised.addrs, vec![v6]);
}

/// A multi-port bind with no IPv4 socket has nothing a peer on the v4 query path could dial: a named
/// error, never a partial or guessed advertisement.
#[test]
fn a_multi_port_bind_without_a_v4_socket_is_an_error() {
    let v6: SocketAddr = "[::1]:1000".parse().expect("a valid v6 address");
    let v6_other: SocketAddr = "[::2]:2000".parse().expect("a valid v6 address");

    assert!(matches!(
        Advertised::of([v6, v6_other]),
        Err(MdnsError::NoV4Addrs)
    ));
}

/// No addresses at all is the named error, not a panic on the empty set.
#[test]
fn an_empty_bind_is_an_error() {
    assert!(matches!(Advertised::of([]), Err(MdnsError::NoAddrs)));
}

/// Two nodes advertising on the LAN resolve each other's advertised address over mDNS.
#[tokio::test]
#[ignore = "drives real multicast; run locally with --ignored"]
async fn two_nodes_resolve_each_other_over_mdns() {
    let (alice, alice_addr) = (node(1), addr(4001));
    let (bob, bob_addr) = (node(2), addr(4002));

    // Hold both guards for the whole test: dropping one stops its advertisement.
    let alice_mdns = MdnsDiscovery::advertise(alice, [alice_addr]).expect("alice advertises");
    let bob_mdns = MdnsDiscovery::advertise(bob, [bob_addr]).expect("bob advertises");

    // Each resolves the OTHER: alice learns bob's addr, bob learns alice's, both from the network.
    let found_bob = resolve_within(&alice_mdns, bob, Duration::from_secs(10)).await;
    let found_alice = resolve_within(&bob_mdns, alice, Duration::from_secs(10)).await;

    assert!(
        found_bob.contains(&bob_addr),
        "alice should resolve bob's advertised addr, got {found_bob:?}"
    );
    assert!(
        found_alice.contains(&alice_addr),
        "bob should resolve alice's advertised addr, got {found_alice:?}"
    );
}

/// A miss resolves to empty (not an error), so a layered caller falls through gracefully.
#[tokio::test]
#[ignore = "drives real multicast; run locally with --ignored"]
async fn unknown_peer_resolves_empty() {
    let mdns = MdnsDiscovery::advertise(node(3), [addr(4003)]).expect("advertises");
    let addrs = mdns.resolve(node(99)).await.expect("resolve never errors");
    assert!(
        addrs.is_empty(),
        "an unheard peer resolves empty, got {addrs:?}"
    );
}

/// Readiness is per-target: an observation of another peer (the dialing node's own advertisement
/// echoed back by multicast loopback) must not release a wait for the target. The paused clock
/// proves the release comes from the target's record, not from elapsed time.
#[tokio::test(start_paused = true)]
async fn wait_ready_holds_through_a_self_observation() {
    let (mdns, peers, observations) = bare_mdns();
    let target = node(41);

    let waiting = {
        let mdns = Arc::clone(&mdns);
        tokio::spawn(async move { mdns.wait_ready(target, Duration::from_secs(5)).await })
    };
    // Let the waiter subscribe and reach its first await.
    tokio::task::yield_now().await;

    // The self-echo lands: an observation of a different identity. The wait must carry on.
    observations.send_replace(());
    tokio::task::yield_now().await;
    assert!(
        !waiting.is_finished(),
        "a self observation must not release the wait"
    );

    // The target's record lands: now the wait releases.
    peers
        .lock()
        .expect("peer table is never poisoned")
        .insert(target, vec![addr(4041)]);
    observations.send_replace(());
    waiting
        .await
        .expect("the wait completes once the target is heard");

    // Released early by the target, so no full browse window has passed and the instance stays cold.
    assert!(!mdns.warmed.load(Ordering::Acquire));
}

/// A wait that runs out its bound marks the instance warm, so a later empty resolve answers at once
/// instead of paying the bound again. The paused clock lets the bound elapse with no wall time.
#[tokio::test(start_paused = true)]
async fn wait_ready_marks_warm_when_the_bound_elapses() {
    let (mdns, _peers, _observations) = bare_mdns();

    let waiting = {
        let mdns = Arc::clone(&mdns);
        tokio::spawn(async move { mdns.wait_ready(node(42), Duration::from_secs(2)).await })
    };
    tokio::task::yield_now().await;
    assert!(
        !waiting.is_finished(),
        "an unheard target holds the wait to its bound"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    waiting.await.expect("the bound releases the wait");
    assert!(mdns.warmed.load(Ordering::Acquire));
}

/// Readiness releases on the TARGET over real multicast. A fresh browser hears its own
/// advertisement echoed back first, which must not release a wait for the peer; once the peer's
/// record lands the wait returns and the peer resolves.
#[tokio::test]
#[ignore = "drives real multicast; run locally with --ignored"]
async fn wait_ready_releases_on_the_target_over_mdns() {
    let alice = node(51);
    let bob = node(52);
    let bob_addr = addr(4052);

    let alice_mdns = MdnsDiscovery::advertise(alice, [addr(4051)]).expect("alice advertises");
    let bob_mdns = MdnsDiscovery::advertise(bob, [bob_addr]).expect("bob advertises");

    alice_mdns.wait_ready(bob, Duration::from_secs(10)).await;

    let found = alice_mdns.resolve(bob).await.expect("resolve never errors");
    assert!(
        found.contains(&bob_addr),
        "alice should resolve bob after readiness releases, got {found:?}"
    );
    drop(bob_mdns);
}

/// A live-shaped instance with no service behind it: the table and observation stream are the
/// handles a test injects through, wired exactly as `advertise` wires them.
fn bare_mdns() -> (Arc<MdnsDiscovery>, super::Peers, watch::Sender<()>) {
    let peers: super::Peers = Arc::new(Mutex::new(HashMap::new()));
    let (observations, _) = watch::channel(());
    let mdns = Arc::new(MdnsDiscovery {
        peers: Arc::clone(&peers),
        observations: observations.clone(),
        warmed: AtomicBool::new(false),
        _service: None,
    });
    (mdns, peers, observations)
}

/// Poll `resolve` until it yields a non-empty result or the deadline passes, returning what it found.
async fn resolve_within(mdns: &MdnsDiscovery, node: NodeId, budget: Duration) -> Vec<SocketAddr> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let addrs = mdns.resolve(node).await.expect("resolve never errors");
        if !addrs.is_empty() || tokio::time::Instant::now() >= deadline {
            return addrs;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
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
