//! mDNS discovery for the local network.
//!
//! [`MdnsDiscovery`] is a [`bifrost::Discovery`](bifrost_core::Discovery) that both ADVERTISES
//! this node and LEARNS peers over multicast DNS, so two nodes on the same LAN reach each other
//! directly with no relay and no hand-fed direct address hint. It is transport-blind: composed into a
//! `Node` beside any transport, it feeds the same `SocketAddr` hints a static table would, only
//! learned from the network instead of typed by hand.
//!
//! It advertises this node's [`NodeId`] mapped to its local `SocketAddr`(s) and continuously browses
//! for the same service, building a table of the peers it hears. A
//! [`subscribe`](Discovery::subscribe) is a view over that table for one node: it answers with the
//! peer's LAN addresses as soon as they are heard, and follows them as they change or expire.
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
//! interactive cadence), so a subscription for a node not yet heard stays quiet for one settle
//! window from the start of the service and then says [`Settled`](AddrUpdate::Settled): the source's
//! own statement that its first look is done. The window belongs to this source because the cadence
//! does; a dial never adds a wait of its own.
//!
//! This is LAN-only by construction: multicast does not cross subnets, so WAN discovery (pkarr/DHT)
//! is a separate mechanism layered above, not a job for this crate.

use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bifrost_core::{AddrUpdate, Discovery, HintStream, Latest, NodeId};
use futures_util::stream;
use swarm_discovery::{Discoverer, IpClass, Peer};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::time::{self, Instant};

mod host;
mod publish;

pub use host::{At, Dialable, Expiring, Missing, Scope, ScopeClass};
pub use publish::{Advertised, Advertising};

/// The mDNS service all theia nodes advertise and browse under: `_theia._udp.local.`.
///
/// A single shared service name is what lets any two theia nodes find each other regardless of which
/// transport each bound: discovery names WHO, the transport decides HOW.
const SERVICE: &str = "theia";

/// How long a fresh browse gets to hear a node before a miss is final for this source.
///
/// Measured from the start of the service, not from a dial: the browse sends its first query on
/// its cadence (a little under a second out at the interactive tau and phi), and one
/// query-response cycle with margin fits inside this. After it, a subscription for a node not heard
/// settles at once, so a long-lived node never pays it again.
const SETTLE_WINDOW: Duration = Duration::from_millis(1500);

/// LAN discovery over mDNS: advertises this node and learns peers heard on the local network.
///
/// Construction starts the service immediately (advertising as well, where the bind gives it
/// something to advertise) and spawns the background browser; the returned value owns the running
/// service and stops it when dropped. Hold it for as long as the node should be discoverable.
///
/// Every subscription reads the one browse this value owns: subscribing starts no query and no task,
/// so N dials cost the LAN nothing more than one.
pub struct MdnsDiscovery {
    /// What the browse has heard, shared with the browse callback (its only writer) and every live
    /// subscription. `None` for a [`disabled`] instance, which will never hear anything.
    ///
    /// [`disabled`]: Self::disabled
    heard: Option<Arc<Heard>>,
    /// Keeps the advertise + browse tasks alive. Dropping it stops the mDNS service, so it is held
    /// purely for its `Drop`; the field is read only by the destructor. `None` for a [`disabled`]
    /// instance, which advertises and hears nothing.
    ///
    /// [`disabled`]: Self::disabled
    _service: Option<swarm_discovery::DropGuard>,
}

/// The maximum number of distinct peers held in the discovery cache. A LAN has a handful of peers, so
/// this is generous; the cap stops an on-LAN flood of distinct fake NodeIds (which anyone can emit, no
/// secret needed) from growing this map without bound. It bounds OUR map only; the wrapped
/// `swarm-discovery` keeps its own unbounded map, which needs a dependency-level fix (patch, fork, or
/// replace).
const MAX_PEERS: usize = 1024;

/// The most addresses held for one peer. A real host advertises a handful; the cap stops one forged
/// record from inflating a peer's hint set, and every dial of it, without bound.
const MAX_HINTS: usize = 8;

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
    /// Peers are learned in the background; a subscription made right after this call hears a peer
    /// once the first discovery cycle has run.
    ///
    /// Must be called from within a Tokio runtime: the mDNS service spawns onto the current handle.
    pub fn advertise(
        node: NodeId,
        bound: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Started, MdnsError> {
        let advertising = Advertising::of(bound.into_iter().collect());

        let heard = Arc::new(Heard::new(Instant::now() + SETTLE_WINDOW));
        let sink = Arc::clone(&heard);
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
            .with_callback(move |peer_id, peer| sink.record(peer_id, peer));
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
                heard: Some(heard),
                _service: Some(service),
            },
            advertising,
        })
    }

    /// A discovery that advertises and hears nothing.
    ///
    /// The honest fallback when the mDNS service cannot start at all (multicast blocked): it keeps
    /// the composed discovery type unchanged so a caller layers it exactly as a live one, and every
    /// subscription has already ended, so the caller falls through to its other sources at once.
    ///
    /// Having nothing to advertise is NOT this: that node still browses and still hears peers, which
    /// [`advertise`](Self::advertise) reports as [`Advertising::BrowseOnly`].
    pub fn disabled() -> Self {
        Self {
            heard: None,
            _service: None,
        }
    }
}

impl Discovery for MdnsDiscovery {
    /// Follow what the browse hears for `node`.
    ///
    /// The feed answers with the peer's LAN addresses as soon as they are heard, or says
    /// [`Settled`](AddrUpdate::Settled) once the settle window from the start of the service has
    /// passed without them; after that it follows changes and expiry. Observations of OTHER peers
    /// (the dialing node's own advertisement echoed back included) never wake it, so only the
    /// subscribed node's record can release a dial waiting on it.
    ///
    /// A feed that outlives the service it came from ends: dropping the service closes every wake
    /// channel, so no subscriber waits on a browse that has stopped.
    fn subscribe(&self, node: NodeId) -> HintStream {
        let Some(heard) = &self.heard else {
            return HintStream::ended();
        };
        let subscription = Subscription {
            node,
            changes: heard.watch(node),
            heard: Arc::clone(heard),
            said: Latest::default(),
        };
        HintStream::new(stream::unfold(
            subscription,
            |mut subscription| async move {
                let update = subscription.next().await?;
                Some((Ok(update), subscription))
            },
        ))
    }
}

impl Drop for MdnsDiscovery {
    /// End every live feed. Each holds the shared table, which outlives this value, so its wake
    /// sender would otherwise never drop and the feed would stay pending on a service that can say
    /// no more. Dropping the senders ends each feed at its next wait, after what the table already
    /// held has been said.
    fn drop(&mut self) {
        if let Some(heard) = &self.heard {
            heard.table().watchers.clear();
        }
    }
}

/// What the browse has heard, and when a miss becomes final.
struct Heard {
    /// A `Mutex` (not a channel) because the browse callback is synchronous and every access is a
    /// short map read or write, never held across an await.
    table: Mutex<Table>,
    /// When a subscription may first say [`Settled`](AddrUpdate::Settled): the start of the
    /// service plus [`SETTLE_WINDOW`], so the browse has had one full window to hear the node.
    settles_at: Instant,
}

/// The peers heard on the LAN, and who is waiting to hear about which of them.
#[derive(Default)]
struct Table {
    peers: HashMap<NodeId, Vec<SocketAddr>>,
    /// One wake channel per node someone is subscribed to. Per node, so an observation of one peer
    /// wakes only that peer's subscribers and a flood on other keys wakes no one else. A `watch`
    /// because a wake only says "re-read the table": it holds no value, so a burst of them
    /// collapses into one. Entries are made by [`Heard::watch`] alone, so their number is bounded by
    /// this process's own subscriptions, never by the network.
    watchers: HashMap<NodeId, watch::Sender<()>>,
}

impl Heard {
    fn new(settles_at: Instant) -> Self {
        Self {
            table: Mutex::new(Table::default()),
            settles_at,
        }
    }

    /// A panic can only have come from an allocation inside a map write, which leaves the map
    /// itself sound, so a poisoned lock is recovered rather than turning every later dial into one.
    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a browse observation, keyed by the peer's parsed [`NodeId`].
    ///
    /// The peer's instance name is a theia [`NodeId`] string; anything that does not parse (a foreign
    /// service instance sharing the name) is ignored rather than erroring. An expired peer is dropped
    /// from the table so a stale address is never offered.
    fn record(&self, peer_id: &str, peer: &Peer) {
        let Ok(node) = peer_id.parse::<NodeId>() else {
            tracing::trace!(peer_id, "ignoring non-theia mDNS instance");
            return;
        };
        if peer.is_expiry() {
            self.forget(node);
            return;
        }
        let hints = shape(
            peer.addrs()
                .iter()
                .map(|(ip, port)| SocketAddr::new(*ip, *port)),
        );
        tracing::debug!(node = %node.short(), count = hints.len(), "discovered peer over mDNS");
        self.learn(node, hints);
    }

    /// Hold `hints` for `node` and wake its subscribers. The wake follows the write, so a woken
    /// subscription always re-reads a table that already includes it.
    fn learn(&self, node: NodeId, hints: Vec<SocketAddr>) {
        let mut table = self.table();
        // Refuse a NEW entry past the cap so an on-LAN flood of distinct fake NodeIds cannot grow
        // this map without bound. A known peer still updates, so real churn is unaffected.
        if table.peers.len() >= MAX_PEERS && !table.peers.contains_key(&node) {
            return;
        }
        table.peers.insert(node, hints);
        table.wake(node);
    }

    /// Drop `node` from the table and wake its subscribers.
    fn forget(&self, node: NodeId) {
        let mut table = self.table();
        table.peers.remove(&node);
        table.wake(node);
    }

    /// What is held for `node` right now; empty when nothing is.
    fn held(&self, node: NodeId) -> Vec<SocketAddr> {
        self.table().peers.get(&node).cloned().unwrap_or_default()
    }

    /// A wake receiver for `node`, created with the current state already seen.
    ///
    /// Channels no subscription holds any more are pruned here, the one place entries are made, so
    /// the map never holds more than the live subscriptions plus the one being made.
    fn watch(&self, node: NodeId) -> watch::Receiver<()> {
        let mut table = self.table();
        table
            .watchers
            .retain(|_, sender| sender.receiver_count() > 0);
        table
            .watchers
            .entry(node)
            .or_insert_with(|| watch::channel(()).0)
            .subscribe()
    }
}

impl Table {
    fn wake(&self, node: NodeId) {
        if let Some(sender) = self.watchers.get(&node) {
            sender.send_replace(());
        }
    }
}

/// One node's feed: a view over the shared table, re-read on every wake for that node.
struct Subscription {
    node: NodeId,
    heard: Arc<Heard>,
    changes: watch::Receiver<()>,
    said: Latest,
}

impl Subscription {
    /// The next thing worth saying about this node, or `None` once no more can ever come.
    async fn next(&mut self) -> Option<AddrUpdate> {
        loop {
            // Mark the wake seen BEFORE reading: a write that lands after the read bumps the
            // channel again, so the await below returns at once instead of losing it.
            self.changes.borrow_and_update();
            let settled = Instant::now() >= self.heard.settles_at;
            if let Some(update) = self.said.say(self.heard.held(self.node), settled) {
                return Some(update);
            }
            let changed = if self.said.said_nothing() {
                // Nothing said yet: the end of the settle window is itself a change worth waking for.
                time::timeout_at(self.heard.settles_at, self.changes.changed())
                    .await
                    .unwrap_or(Ok(()))
            } else {
                self.changes.changed().await
            };
            changed.ok()?;
        }
    }
}

/// A peer's advertised addresses as a hint set: deduplicated, the most widely reachable first, and
/// capped at [`MAX_HINTS`].
///
/// Order matters because a direct-only transport dials the first hint alone, so a peer's own
/// loopback address (which reaches it only from its own host) must never take that slot from one a
/// LAN peer can use. This orders; it does not authenticate: whoever forges the record still chooses
/// every address in it.
fn shape(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut hints: Vec<SocketAddr> = Vec::new();
    for addr in addrs {
        if !hints.contains(&addr) {
            hints.push(addr);
        }
    }
    hints.sort_by_key(|addr| Span::of(addr.ip()));
    hints.truncate(MAX_HINTS);
    hints
}

/// How widely an advertised address reaches, in the order a hint set offers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Span {
    /// Routable beyond one link: a LAN or public address.
    Routed,
    /// This link only.
    Link,
    /// The advertising host only.
    Host,
}

impl Span {
    fn of(ip: IpAddr) -> Self {
        match ip {
            ip if ip.is_loopback() => Self::Host,
            IpAddr::V4(v4) if v4.is_link_local() => Self::Link,
            IpAddr::V6(v6) if v6.is_unicast_link_local() => Self::Link,
            IpAddr::V4(_) | IpAddr::V6(_) => Self::Routed,
        }
    }
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
