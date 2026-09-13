//! mDNS discovery for the local network.
//!
//! [`MdnsDiscovery`] is a [`bifrost::Discovery`](bifrost_core::Discovery) that both ADVERTISES
//! this node and RESOLVES peers over multicast DNS, so two nodes on the same LAN reach each other
//! directly with no relay and no hand-fed direct address hint. It is transport-blind: composed into a
//! `Node` beside any transport, it feeds the same `SocketAddr` hints a static table would, only
//! learned from the network instead of typed by hand.
//!
//! It advertises this node's [`NodeId`] mapped to its local `SocketAddr`(s) and continuously browses
//! for the same service, building a table of the peers it hears. [`resolve`](MdnsDiscovery::resolve)
//! reads that table: a hit returns the peer's LAN addresses, a miss returns empty so the caller falls
//! through to whatever discovery it is layered with (an explicit hint, or the transport's own).
//!
//! The browse learns nothing until its first query-response cycle (roughly a second out with the
//! interactive cadence), so [`wait_ready`](Discovery::wait_ready) gives a dial a bounded wait for
//! that cycle before a miss is treated as final.
//!
//! This is LAN-only by construction: multicast does not cross subnets, so WAN discovery (pkarr/DHT)
//! is a separate mechanism layered above, not a job for this crate.

use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bifrost_core::{Discovery, Error, NodeId};
use swarm_discovery::{Discoverer, IpClass, Peer};
use tokio::runtime::Handle;
use tokio::sync::Notify;

/// The mDNS service all theia nodes advertise and browse under: `_theia._udp.local.`.
///
/// A single shared service name is what lets any two theia nodes find each other regardless of which
/// transport each bound: discovery names WHO, the transport decides HOW.
const SERVICE: &str = "theia";

/// LAN discovery over mDNS: advertises this node and resolves peers heard on the local network.
///
/// Construction starts advertising immediately and spawns the background browser; the returned value
/// owns the running service and stops it when dropped. Hold it for as long as the node should be
/// discoverable. A fresh instance can resolve nothing until its first browse cycle has run (about a
/// second out), so [`wait_ready`](Discovery::wait_ready) is the bounded wait a dial uses to tell a
/// cold start from an absent peer.
pub struct MdnsDiscovery {
    /// Peers heard on the LAN, keyed by identity. Shared with the browse callback, which is the only
    /// writer; [`resolve`](Self::resolve) is the only reader. A `Mutex` (not a channel) because the
    /// access is a trivial, non-blocking map read/write behind an async method, not a stream to drive.
    peers: Peers,
    /// Wakes a [`wait_ready`](Discovery::wait_ready) caller on the first browse observation. Shared
    /// with the browse callback, which is the only notifier.
    observed: Arc<Notify>,
    /// Set once a readiness wait has ended, whether an observation woke it or the bound elapsed (the
    /// browse cycle has run by then). Later waits answer at once, so only the first cold dial pays.
    /// A plain field: only `wait_ready` reads or writes it.
    warmed: AtomicBool,
    /// Keeps the advertise + browse tasks alive. Dropping it stops the mDNS service, so it is held
    /// purely for its `Drop`; the field is read only by the destructor. `None` for a [`disabled`]
    /// instance, which advertises and resolves nothing.
    ///
    /// [`disabled`]: Self::disabled
    _service: Option<swarm_discovery::DropGuard>,
}

/// The shared table of LAN peers, written by the browse callback and read by [`MdnsDiscovery::resolve`].
type Peers = Arc<Mutex<HashMap<NodeId, Vec<SocketAddr>>>>;

/// The maximum number of distinct peers held in the discovery cache. A LAN has a handful of peers, so
/// this is generous; the cap stops an on-LAN flood of distinct fake NodeIds (which anyone can emit, no
/// secret needed) from growing this map without bound. It bounds OUR map only; the wrapped
/// `swarm-discovery` keeps its own unbounded map, which needs a dependency-level fix (patch, fork, or
/// replace); see notes/reviews/2026-08-28-adversary-mdns.md.
const MAX_PEERS: usize = 1024;

impl MdnsDiscovery {
    /// Start advertising `node` at its local `addrs` and browsing the LAN for other theia nodes.
    ///
    /// `addrs` are the sockets this node is bound to (the addresses a caller has after bind). Every address must
    /// share one port: mDNS advertises a service instance as one port plus a set of IPs, so a single
    /// call maps one port to many addresses. Peers are learned in the background; a freshly started
    /// node may need a discovery cycle before [`resolve`](Self::resolve) sees a given peer.
    ///
    /// Must be called from within a Tokio runtime: the mDNS service spawns onto the current handle.
    pub fn advertise(
        node: NodeId,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Self, MdnsError> {
        let addrs = addrs.into_iter().collect::<Vec<_>>();
        let port = single_port(&addrs)?;
        // Pin multicast egress to the interfaces we advertise on. Without this the kernel picks the
        // egress interface off the routing table, which can miss a multi-homed peer (and never loops
        // a loopback-only advertisement back to a same-host browser). One entry per bound IPv4.
        let interfaces = addrs
            .iter()
            .filter_map(|addr| match addr.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect::<Vec<_>>();
        let ips = addrs.into_iter().map(|addr| addr.ip());

        let peers: Peers = Arc::new(Mutex::new(HashMap::new()));
        let sink = Arc::clone(&peers);
        let observed = Arc::new(Notify::new());
        let signal = Arc::clone(&observed);
        // `new_interactive` sets a human-facing cadence (tau=0.7s, phi=2.5): a person is waiting on an
        // interactive probe, so bias toward finding a peer within a second over minimizing multicast chatter.
        let service = Discoverer::new_interactive(SERVICE.to_owned(), node.to_string())
            // V4Only: the dependency's IPv6 leg always egresses the default interface, sending to the
            // link-local mDNS group with scope 0. On a host without an IPv6 path that send fails per
            // query (EHOSTUNREACH, hundreds of WARN lines in minutes), and the leg runs at all only as
            // a side effect of the v4 interface pinning above. Queries are v4-preferred regardless and
            // a response can still carry AAAA records, so this drops only the narrow v6-only reach for
            // a quiet, deterministic v4 path; a real v4 send failure still warns per interface.
            .with_ip_class(IpClass::V4Only)
            .with_addrs(port, ips)
            .with_multicast_interfaces_v4(interfaces)
            .with_callback(move |peer_id, peer| record(&sink, &signal, peer_id, peer))
            .spawn(&Handle::current())
            .map_err(|err| MdnsError::Spawn(Box::new(err)))?;

        Ok(Self {
            peers,
            observed,
            warmed: AtomicBool::new(false),
            _service: Some(service),
        })
    }

    /// A discovery that advertises and resolves nothing.
    ///
    /// The honest fallback when mDNS cannot start (multicast blocked, no local addresses): it keeps the
    /// composed discovery type unchanged so a caller layers it exactly as a live one, and every
    /// [`resolve`](Self::resolve) returns empty so the caller falls through to its other sources.
    /// There is nothing to warm, so [`wait_ready`](Discovery::wait_ready) returns at once.
    pub fn disabled() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            observed: Arc::new(Notify::new()),
            warmed: AtomicBool::new(true),
            _service: None,
        }
    }
}

impl Discovery for MdnsDiscovery {
    /// Return the LAN addresses heard for `node`, or empty if none have been (yet) discovered.
    ///
    /// Empty is not an error: it means "I have not heard this peer", and the caller falls through to
    /// the discovery this is layered with. A poisoned lock (a callback panicked) degrades to empty
    /// rather than propagating, since a discovery miss is always a safe fallback.
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        let Ok(peers) = self.peers.lock() else {
            return Ok(Vec::new());
        };
        Ok(peers.get(&node).cloned().unwrap_or_default())
    }

    /// Wait for the first browse observation, or for the bound to elapse.
    ///
    /// The browse sends its first query on its cadence, so a resolve that runs earlier misses a peer
    /// that is in fact on the network. An observation wakes this at once; otherwise the bound stands
    /// in for the first cycle. Either way the wait ends warm, so only the first cold dial pays it and
    /// later empty resolves answer immediately.
    async fn wait_ready(&self, timeout: Duration) {
        if self.warmed.load(Ordering::Acquire) {
            return;
        }
        let _ = tokio::time::timeout(timeout, self.observed.notified()).await;
        self.warmed.store(true, Ordering::Release);
    }
}

/// Record a browse observation into the shared table, keyed by the peer's parsed [`NodeId`], and wake
/// any readiness wait: a parsed observation proves the browse is live, including a peer expiring.
///
/// The peer's instance name is a theia [`NodeId`] string; anything that does not parse (a foreign
/// service instance sharing the name) is ignored rather than erroring. An expired peer (no addresses)
/// is dropped from the table so a stale address is never resolved.
fn record(peers: &Peers, observed: &Notify, peer_id: &str, peer: &Peer) {
    let Ok(node) = peer_id.parse::<NodeId>() else {
        tracing::trace!(peer_id, "ignoring non-theia mDNS instance");
        return;
    };
    let Ok(mut peers) = peers.lock() else {
        return;
    };
    observed.notify_one();
    if peer.is_expiry() {
        peers.remove(&node);
        return;
    }
    // Bound the cache: refuse a NEW entry past the cap so an on-LAN flood of distinct fake NodeIds cannot
    // grow this map without bound. A known peer still updates, so real churn is unaffected.
    if peers.len() >= MAX_PEERS && !peers.contains_key(&node) {
        return;
    }
    let addrs = peer
        .addrs()
        .iter()
        .map(|(ip, port)| SocketAddr::new(*ip, *port))
        .collect::<Vec<_>>();
    tracing::debug!(node = %node.short(), count = addrs.len(), "discovered peer over mDNS");
    peers.insert(node, addrs);
}

/// The one port a set of local addresses shares, or an error if they disagree or the set is empty.
///
/// mDNS advertises a service instance as a single port with a set of IPs, so every bound address must
/// share one port. Nodes bind one listener across interfaces, so this holds in practice; the check
/// makes a violation a clear error instead of silently advertising the wrong port.
fn single_port(addrs: &[SocketAddr]) -> Result<u16, MdnsError> {
    let mut ports = addrs.iter().map(SocketAddr::port);
    let port = ports.next().ok_or(MdnsError::NoAddrs)?;
    match ports.all(|other| other == port) {
        true => Ok(port),
        false => Err(MdnsError::MixedPorts),
    }
}

/// Why starting mDNS discovery failed.
#[derive(Debug, thiserror::Error)]
pub enum MdnsError {
    /// No local addresses were supplied to advertise.
    #[error("no local addresses to advertise")]
    NoAddrs,
    /// The local addresses did not share a single port.
    #[error("local addresses span multiple ports")]
    MixedPorts,
    /// The mDNS service could not be spawned (socket bind or service-name error).
    ///
    /// Boxed because `SpawnError` is large (>128 bytes); keeping it inline would bloat every
    /// `Result<_, MdnsError>` in the crate for a cold error path.
    #[error("spawn mdns service")]
    Spawn(#[source] Box<swarm_discovery::SpawnError>),
}

#[cfg(test)]
mod lib_tests;
