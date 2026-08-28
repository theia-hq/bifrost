//! mDNS discovery for the local network.
//!
//! [`MdnsDiscovery`] is a [`bifrost::Discovery`](bifrost_core::Discovery) that both ADVERTISES
//! this node and RESOLVES peers over multicast DNS, so two nodes on the same LAN reach each other
//! directly with no relay and no hand-fed `--peer` hint. It is transport-blind: composed into a
//! `Node` beside any transport, it feeds the same `SocketAddr` hints a static table would, only
//! learned from the network instead of typed by hand.
//!
//! It advertises this node's [`NodeId`] mapped to its local `SocketAddr`(s) and continuously browses
//! for the same service, building a table of the peers it hears. [`resolve`](MdnsDiscovery::resolve)
//! reads that table: a hit returns the peer's LAN addresses, a miss returns empty so the caller falls
//! through to whatever discovery it is layered with (an explicit hint, or the transport's own).
//!
//! This is LAN-only by construction: multicast does not cross subnets, so WAN discovery (pkarr/DHT)
//! is a separate mechanism layered above, not a job for this crate.

use core::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bifrost_core::{Discovery, Error, NodeId};
use swarm_discovery::{Discoverer, Peer};
use tokio::runtime::Handle;

/// The mDNS service all theia nodes advertise and browse under: `_theia._udp.local.`.
///
/// A single shared service name is what lets any two theia nodes find each other regardless of which
/// transport each bound: discovery names WHO, the transport decides HOW.
const SERVICE: &str = "theia";

/// LAN discovery over mDNS: advertises this node and resolves peers heard on the local network.
///
/// Construction starts advertising immediately and spawns the background browser; the returned value
/// owns the running service and stops it when dropped. Hold it for as long as the node should be
/// discoverable.
pub struct MdnsDiscovery {
    /// Peers heard on the LAN, keyed by identity. Shared with the browse callback, which is the only
    /// writer; [`resolve`](Self::resolve) is the only reader. A `Mutex` (not a channel) because the
    /// access is a trivial, non-blocking map read/write behind an async method, not a stream to drive.
    peers: Peers,
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
/// replace) — see notes/reviews/2026-08-28-adversary-mdns.md.
const MAX_PEERS: usize = 1024;

impl MdnsDiscovery {
    /// Start advertising `node` at its local `addrs` and browsing the LAN for other theia nodes.
    ///
    /// `addrs` are the sockets this node is bound to (what swoosh has after bind). Every address must
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
        // `new_interactive` sets a human-facing cadence (tau=0.7s, phi=2.5): a person waits on `swoosh
        // ping`, so bias toward finding a peer within a second over minimizing multicast chatter.
        let service = Discoverer::new_interactive(SERVICE.to_owned(), node.to_string())
            .with_addrs(port, ips)
            .with_multicast_interfaces_v4(interfaces)
            .with_callback(move |peer_id, peer| record(&sink, peer_id, peer))
            .spawn(&Handle::current())
            .map_err(|err| MdnsError::Spawn(Box::new(err)))?;

        Ok(Self {
            peers,
            _service: Some(service),
        })
    }

    /// A discovery that advertises and resolves nothing.
    ///
    /// The honest fallback when mDNS cannot start (multicast blocked, no local addresses): it keeps the
    /// composed discovery type unchanged so a caller layers it exactly as a live one, and every
    /// [`resolve`](Self::resolve) returns empty so the caller falls through to its other sources.
    pub fn disabled() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
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
}

/// Record a browse observation into the shared table, keyed by the peer's parsed [`NodeId`].
///
/// The peer's instance name is a theia [`NodeId`] string; anything that does not parse (a foreign
/// service instance sharing the name) is ignored rather than erroring. An expired peer (no addresses)
/// is dropped from the table so a stale address is never resolved.
fn record(peers: &Peers, peer_id: &str, peer: &Peer) {
    let Ok(node) = peer_id.parse::<NodeId>() else {
        tracing::trace!(peer_id, "ignoring non-theia mDNS instance");
        return;
    };
    let Ok(mut peers) = peers.lock() else {
        return;
    };
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
