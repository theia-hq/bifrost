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
//! What it advertises comes from bind truth: the caller hands
//! [`advertise`](MdnsDiscovery::advertise) the sockets its transport actually bound, and this crate
//! decides what of that is publishable, expanding a wildcard bind into this host's real addresses
//! and leaving a deliberate loopback bind exactly as it is. [`Advertising`] names what the result
//! reaches, so a surface can report the truth rather than assume a LAN record went out.
//!
//! That expansion is public as [`Dialable`], because a bind answers on more addresses than a record
//! may carry: a surface that hands a person an address to dial by hand wants the tunnel address and
//! the loopback one that no record may name. Each entry says how far it reaches ([`Scope`]), so
//! every consumer applies its OWN rule to the same fact instead of reading a report about what this
//! crate published. The set also says what it is [`Missing`], so a surface that hands over a short
//! list can say why it is short rather than presenting it as everything this host has.
//!
//! The browse learns nothing until its first query-response cycle (roughly a second out with the
//! interactive cadence), so [`wait_ready`](Discovery::wait_ready) gives a dial a bounded wait for
//! that cycle before a miss is treated as final.
//!
//! This is LAN-only by construction: multicast does not cross subnets, so WAN discovery (pkarr/DHT)
//! is a separate mechanism layered above, not a job for this crate.

use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use bifrost_core::{Discovery, Error, NodeId};
use swarm_discovery::{Discoverer, IpClass, Peer};
use tokio::runtime::Handle;
use tokio::sync::watch;

mod host;
mod publish;

pub use host::{At, Dialable, Expiring, Missing, Scope, ScopeClass};
pub use publish::{Advertised, Advertising};

/// The mDNS service all theia nodes advertise and browse under: `_theia._udp.local.`.
///
/// A single shared service name is what lets any two theia nodes find each other regardless of which
/// transport each bound: discovery names WHO, the transport decides HOW.
const SERVICE: &str = "theia";

/// LAN discovery over mDNS: advertises this node and resolves peers heard on the local network.
///
/// Construction starts the service immediately (advertising as well, where the bind gives it
/// something to advertise) and spawns the background browser; the returned value owns the running
/// service and stops it when dropped. Hold it for as long as the node should be discoverable. A
/// fresh instance can resolve nothing until its first browse cycle has run (about a second out), so
/// [`wait_ready`](Discovery::wait_ready) is the bounded, per-peer wait a dial uses to tell a cold
/// start from an absent peer.
pub struct MdnsDiscovery {
    /// Peers heard on the LAN, keyed by identity. Shared with the browse callback, which is the only
    /// writer; [`resolve`](Self::resolve) and [`wait_ready`](Discovery::wait_ready) are the readers. A
    /// `Mutex` (not a channel) because the access is a trivial, non-blocking map read/write behind an
    /// async method, not a stream to drive.
    peers: Peers,
    /// Advances on every parsed browse observation. A readiness wait watches it to re-check its
    /// target, so an observation of any other peer (the dialing node's own echo included) only wakes
    /// the wait, never releases it. A `watch` (not a `Notify`) because a bump must reach every
    /// waiter and must not be lost to a waiter that subscribed late.
    observations: watch::Sender<()>,
    /// Set once a readiness wait has run to its bound, proving the browse has had a full window, so
    /// later empty resolves answer at once instead of paying the bound again. A wait released early
    /// by the target does NOT set it: the browse is live, but its own first query may not be out yet.
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
/// replace).
const MAX_PEERS: usize = 1024;

/// A started mDNS service: the live discovery to hold, and what its advertisement reaches.
///
/// The two travel together because the one call that starts the service is the only place the
/// outcome is known: a caller that dropped [`advertising`](Self::advertising) would have to guess it
/// again from addresses it no longer owns.
pub struct Started {
    /// The running discovery. Hold it for as long as the node should be discoverable; dropping it
    /// stops the service.
    pub discovery: MdnsDiscovery,
    /// What the advertisement put on the wire, for a surface to read before it claims a reach.
    pub advertising: Advertising,
}

impl MdnsDiscovery {
    /// Start advertising `node` at the sockets it bound, and browsing the LAN for other theia nodes.
    ///
    /// `bound` is bind truth: the sockets the node's transport is bound to, with an unspecified IP
    /// (`0.0.0.0`, `[::]`) left as bound rather than rewritten to loopback, which is what
    /// `bifrost::Transport::bound_sockets` reports. A wildcard expands into this host's concrete
    /// addresses and a concrete loopback address is published as itself, and the record names one
    /// port, the first IPv4 socket's where the bind spans several ([`Advertised`]). Nothing
    /// publishable is not a failure: the service still browses, and
    /// the returned [`Advertising`] says so with its cause. The one failure left is the service not
    /// starting at all.
    ///
    /// Peers are learned in the background; a freshly started node may need a discovery cycle before
    /// [`resolve`](Self::resolve) sees a given peer.
    ///
    /// Must be called from within a Tokio runtime: the mDNS service spawns onto the current handle.
    pub fn advertise(
        node: NodeId,
        bound: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Started, MdnsError> {
        let advertising = Advertising::of(bound.into_iter().collect());

        let peers: Peers = Arc::new(Mutex::new(HashMap::new()));
        let sink = Arc::clone(&peers);
        let (observations, _) = watch::channel(());
        let signal = observations.clone();
        // `new_interactive` sets a human-facing cadence (tau=0.7s, phi=2.5): a person is waiting on an
        // interactive probe, so bias toward finding a peer within a second over minimizing multicast chatter.
        let mut service = Discoverer::new_interactive(SERVICE.to_owned(), node.to_string())
            // V4Only: the dependency's IPv6 leg always egresses the default interface, sending to the
            // link-local mDNS group with scope 0. On a host without an IPv6 path that send fails per
            // query (EHOSTUNREACH, hundreds of WARN lines in minutes), and the leg runs at all only as
            // a side effect of the v4 interface pinning below. Queries are v4-preferred regardless and
            // a response can still carry AAAA records, so this drops only the narrow v6-only reach for
            // a quiet, deterministic v4 path; a real v4 send failure still warns per interface.
            .with_ip_class(IpClass::V4Only)
            .with_callback(move |peer_id, peer| record(&sink, &signal, peer_id, peer));
        // Registering no addresses is how the dependency spells browse-only: it keeps querying and
        // reading responses, and puts no record of its own on the wire.
        if let Some(advertised) = advertising.advertised() {
            service = service
                .with_addrs(
                    advertised.port(),
                    advertised.addrs().iter().map(SocketAddr::ip),
                )
                .with_multicast_interfaces_v4(advertised.egress_v4());
        }
        let service = service
            .spawn(&Handle::current())
            .map_err(|err| MdnsError::Spawn(Box::new(err)))?;

        Ok(Started {
            discovery: Self {
                peers,
                observations,
                warmed: AtomicBool::new(false),
                _service: Some(service),
            },
            advertising,
        })
    }

    /// A discovery that advertises and resolves nothing.
    ///
    /// The honest fallback when the mDNS service cannot start at all (multicast blocked): it keeps
    /// the composed discovery type unchanged so a caller layers it exactly as a live one, and every
    /// [`resolve`](Self::resolve) returns empty so the caller falls through to its other sources.
    /// There is nothing to warm, so [`wait_ready`](Discovery::wait_ready) returns at once.
    ///
    /// Having nothing to advertise is NOT this: that node still browses and still resolves, which
    /// [`advertise`](Self::advertise) reports as [`Advertising::BrowseOnly`].
    pub fn disabled() -> Self {
        let (observations, _) = watch::channel(());
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            observations,
            warmed: AtomicBool::new(true),
            _service: None,
        }
    }

    /// Whether `node` is currently in the heard table, from an unexpired observation.
    fn known(&self, node: NodeId) -> bool {
        self.peers
            .lock()
            .map(|peers| peers.contains_key(&node))
            .unwrap_or(false)
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

    /// Wait for an observation of `node`, or for the bound to elapse.
    ///
    /// The browse sends its first query on its cadence, so a resolve that runs earlier misses a peer
    /// that is in fact on the network. Observations of OTHER peers (the dialing node's own echo
    /// included) wake this to re-check the table and keep waiting; only an observation of `node`
    /// releases it. Running the bound out marks the instance warm: a full browse window has passed,
    /// so later empty resolves answer at once. A wait released early by the target does not mark it.
    async fn wait_ready(&self, node: NodeId, timeout: Duration) {
        if self.warmed.load(Ordering::Acquire) {
            return;
        }
        // Subscribe before the first table check: a bump that lands after the check still advances
        // this receiver, so an observation between the check and the await is not lost.
        let mut observations = self.observations.subscribe();
        if self.known(node) {
            return;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                self.warmed.store(true, Ordering::Release);
                return;
            }
            match tokio::time::timeout(remaining, observations.changed()).await {
                Ok(Ok(())) if self.known(node) => return,
                Ok(Ok(())) => {}
                Ok(Err(_)) => return,
                Err(_) => {
                    self.warmed.store(true, Ordering::Release);
                    return;
                }
            }
        }
    }
}

/// Record a browse observation into the shared table, keyed by the peer's parsed [`NodeId`], then
/// bump the observation stream so a readiness wait re-checks its target.
///
/// The peer's instance name is a theia [`NodeId`] string; anything that does not parse (a foreign
/// service instance sharing the name) is ignored rather than erroring. An expired peer (no addresses)
/// is dropped from the table so a stale address is never resolved. The bump follows the table update,
/// so a wait woken by it always re-checks a state that already includes this observation.
fn record(peers: &Peers, observations: &watch::Sender<()>, peer_id: &str, peer: &Peer) {
    let Ok(node) = peer_id.parse::<NodeId>() else {
        tracing::trace!(peer_id, "ignoring non-theia mDNS instance");
        return;
    };
    let Ok(mut peers) = peers.lock() else {
        return;
    };
    if peer.is_expiry() {
        peers.remove(&node);
        observations.send_replace(());
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
    observations.send_replace(());
}

/// Why an advertisement could not be made.
///
/// Only [`Spawn`](Self::Spawn) stops the service: the rest name an advertisement that could not be
/// composed, which leaves the node browsing and is carried as the cause of
/// [`Advertising::BrowseOnly`].
#[derive(Debug, thiserror::Error)]
pub enum MdnsError {
    /// No local addresses were supplied to advertise.
    #[error("no local addresses to advertise")]
    NoAddrs,
    /// A multi-port bind held no IPv4 socket, so the one port an advertisement may name would not be
    /// dialable by a peer on this host's IPv4 mDNS query path.
    #[error("no IPv4 address to advertise on a multi-port bind")]
    NoV4Addrs,
    /// A wildcard bind had to be expanded into this host's interface addresses, and the host would
    /// not report them.
    #[error("read this host's interface addresses")]
    Interfaces(#[source] io::Error),
    /// The mDNS service could not be spawned (socket bind or service-name error).
    ///
    /// Boxed because `SpawnError` is large (>128 bytes); keeping it inline would bloat every
    /// `Result<_, MdnsError>` in the crate for a cold error path.
    #[error("spawn mdns service")]
    Spawn(#[source] Box<swarm_discovery::SpawnError>),
}

#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod publish_tests;
