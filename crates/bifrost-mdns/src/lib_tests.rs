//! In-process mDNS round trip: two [`MdnsDiscovery`] instances advertise and resolve each other.
//!
//! This drives real multicast over the loopback/default interface, so it is `#[ignore]`d by default:
//! CI and sandboxed environments routinely block multicast, and a network-dependent test must not
//! flake the suite. Run it locally with `cargo test -p bifrost-mdns -- --ignored` to exercise the
//! full advertise + browse + resolve path against the OS mDNS stack.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;

use bifrost_core::{CryptoKind, Discovery, NodeId};

use super::MdnsDiscovery;

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
