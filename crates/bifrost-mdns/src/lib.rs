//! mDNS discovery for the local network.
//!
//! [`MdnsDiscovery`] is a [`bifrost::Discovery`](bifrost_core::Discovery) that both ADVERTISES
//! this node and LEARNS peers over multicast DNS, so two nodes on the same LAN reach each other
//! directly with no relay and no hand-fed direct address hint. It is transport-blind: composed into a
//! `Node` beside any transport, it feeds the same `SocketAddr` hints a static table would, only
//! learned from the network instead of typed by hand.
//!
//! A serving node announces itself on each local network under a name that changes at every start
//! and every fifteen minutes. Only someone who already holds its key can tell that name is this
//! node; anyone else sees that a bifrost node is present, at an address and port, and not which
//! one. Anyone who dials that port still learns the key from the handshake. A node that only dials
//! announces nothing.
//!
//! It continuously browses for the same service, building a table of the names it hears and which
//! of them belong to a node someone here is subscribed to. A
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
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

use crate::name::Resolver;

mod host;
mod name;
mod publish;

pub use host::{At, Dialable, Expiring, Missing, Scope, ScopeClass};
pub use publish::{Advertised, Advertising};

/// The mDNS service every bifrost node advertises and browses under: `_bifrost._udp.local.`.
///
/// A single shared service name is what lets any two bifrost nodes find each other regardless of which
/// transport each bound: discovery names WHO, the transport decides HOW.
const SERVICE: &str = "bifrost";

/// How long a fresh browse gets to hear a node before a miss is final for this source.
///
/// Measured from the start of the service, not from a dial: the browse sends its first query on
/// its cadence (a little under a second out at the interactive tau and phi), and one
/// query-response cycle with margin fits inside this. After it, a subscription for a node not heard
/// settles at once, so a long-lived node never pays it again.
const SETTLE_WINDOW: Duration = Duration::from_millis(1500);

/// How often a serving node announces under a fresh name, on top of the fresh name at every start.
///
/// Fifteen minutes is Bluetooth's default for rotating a private address. The timer is for the
/// machine that sleeps on one network and wakes on another without restarting; it runs on tokio's
/// clock and never reads the wall clock.
const ROTATE: Duration = Duration::from_secs(15 * 60);

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
    _service: Option<Service>,
}

/// The running mDNS service, and for a serving node the task that renames it.
///
/// The dependency fixes the instance name when a service is built, so a new name is a new service:
/// the rotation task starts the next one, and only then drops the one it replaces, so the node is
/// never silent between the two.
struct Service {
    /// The service running now. Shared with the rotation task, which swaps in each new one.
    current: Arc<Mutex<Option<DropGuard>>>,
    /// The rotation task, for a node that announces. A browse-only node announces no name, so it
    /// runs none.
    rotation: Option<JoinHandle<()>>,
}

impl Drop for Service {
    /// Stop the service here and now, and the rotation with it, so no new service starts after this.
    fn drop(&mut self) {
        if let Some(rotation) = &self.rotation {
            rotation.abort();
        }
        drop(lock(&self.current).take());
    }
}

/// Announce under a fresh name every [`ROTATE`] for as long as `current` holds a service.
///
/// `start` builds and starts a service under the name it is given. The next service is started
/// before the old one is dropped. A name or a service that cannot be made keeps the one running and
/// is tried again at the next turn: the fallback is the current blinded name, never the key.
async fn rotate<G>(
    node: NodeId,
    current: Arc<Mutex<Option<G>>>,
    mut start: impl FnMut(String) -> Result<G, MdnsError>,
) {
    loop {
        time::sleep(ROTATE).await;
        let next = match name::fresh(&node)
            .map_err(MdnsError::Entropy)
            .and_then(&mut start)
        {
            Ok(next) => next,
            Err(err) => {
                tracing::warn!(error = %err, "could not announce under a new mDNS name; keeping the current one");
                continue;
            }
        };
        let old = {
            let mut slot = lock(&current);
            if slot.is_none() {
                return;
            }
            slot.replace(next)
        };
        drop(old);
    }
}

/// A panic under one of these locks can only have come from an allocation inside a map or slot
/// write, which leaves the value itself sound, so a poisoned lock is recovered rather than turning
/// every later dial into one.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The maximum number of distinct names held in the discovery cache. A LAN has a handful of peers,
/// so this is generous; the cap stops an on-LAN flood of distinct names (which anyone can emit, no
/// secret needed) from growing this map without bound. At the cap a new name evicts the oldest name
/// no live subscription is waiting on, so a flood evicts only its own junk and never a peer someone
/// is waiting on. It bounds OUR map only; the wrapped `swarm-discovery` keeps its own unbounded map,
/// which needs a dependency-level fix (patch, fork, or replace).
const MAX_PEERS: usize = 1024;

/// The most names held for one subscribed node. A node is heard under about two at once: its
/// current name, and the one it rotated out of until that expires. Anyone who holds the node's key
/// can mint names that match it without end, so past this a new one takes the place of that node's
/// oldest, and a flood of them never shuts out another peer.
const MAX_NAMES_PER_NODE: usize = 4;

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
    /// Start advertising `node` at the sockets it bound, and browsing the LAN for other bifrost nodes.
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
        let announce = advertising.advertised().map(|advertised| {
            let addrs: Vec<IpAddr> = advertised.addrs().iter().map(SocketAddr::ip).collect();
            (advertised.port(), addrs, advertised.egress_v4())
        });
        let announces = announce.is_some();
        let sink = Arc::clone(&heard);
        let handle = Handle::current();
        // The name is the dependency's `peer_id`, which it puts on the wire twice: as the instance
        // name and inside the SRV target host `<name>-<port>.local.`. A blinded name covers both.
        let start = move |name: String| {
            let sink = Arc::clone(&sink);
            // `new_interactive` sets a human-facing cadence (tau=0.7s, phi=2.5): a person is waiting on an
            // interactive probe, so bias toward finding a peer within a second over minimizing multicast chatter.
            let mut service = Discoverer::new_interactive(SERVICE.to_owned(), name)
                // V4Only: the dependency's IPv6 leg always egresses the default interface, sending to the
                // link-local mDNS group with scope 0. On a host without an IPv6 path that send fails per
                // query (EHOSTUNREACH, hundreds of WARN lines in minutes), and the leg runs at all only as
                // a side effect of the v4 interface pinning below. Queries are v4-preferred regardless and
                // a response can still carry AAAA records, so this drops only the narrow v6-only reach for
                // a quiet, deterministic v4 path; a real v4 send failure still warns per interface.
                .with_ip_class(IpClass::V4Only)
                .with_callback(move |name, peer| sink.record(name, peer));
            // Registering no addresses is how the dependency spells browse-only: it keeps querying and
            // reading responses, and puts no record of its own on the wire.
            if let Some((port, addrs, egress)) = &announce {
                service = service
                    .with_addrs(*port, addrs.iter().copied())
                    .with_multicast_interfaces_v4(egress.clone());
            }
            service
                .spawn(&handle)
                .map_err(|err| MdnsError::Spawn(Box::new(err)))
        };

        let first = start(name::fresh(&node).map_err(MdnsError::Entropy)?)?;
        let current = Arc::new(Mutex::new(Some(first)));
        let rotation = announces.then(|| tokio::spawn(rotate(node, Arc::clone(&current), start)));

        Ok(Started {
            discovery: Self {
                heard: Some(heard),
                _service: Some(Service { current, rotation }),
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

/// The names heard on the LAN, and who is waiting to hear about which node.
#[derive(Default)]
struct Table {
    /// Keyed by the name heard, because a node is heard under a new name at every rotation and
    /// each name expires on its own.
    peers: HashMap<String, Entry>,
    /// One wake channel per node someone is subscribed to. Per node, so an observation of one peer
    /// wakes only that peer's subscribers and a flood of other names wakes no one else. A `watch`
    /// because a wake only says "re-read the table": it holds no value, so a burst of them
    /// collapses into one. Entries are made by [`Heard::watch`] alone, so their number is bounded by
    /// this process's own subscriptions, never by the network. They are also the only keys a heard
    /// name is ever tested against.
    watchers: HashMap<NodeId, Watcher>,
}

/// One name heard on the LAN.
struct Entry {
    /// The subscribed node this name belongs to, or `None` when it matched no subscription. Tested
    /// once, when the name is first heard or when a new subscription arrives, never per record.
    node: Option<NodeId>,
    hints: Vec<SocketAddr>,
    /// When this name was last heard, so the freshest of a node's names answers for it and a full
    /// table evicts the oldest unmatched name first.
    heard: Instant,
}

/// A subscribed node: its subscribers' wake channel, and what recognises its names.
struct Watcher {
    wake: watch::Sender<()>,
    names: Resolver,
}

impl Heard {
    fn new(settles_at: Instant) -> Self {
        Self {
            table: Mutex::new(Table::default()),
            settles_at,
        }
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        lock(&self.table)
    }

    /// Record a browse observation, keyed by the instance name.
    ///
    /// The instance name is a blinded name (see `name`); a name that matches no subscribed key is
    /// held unmatched, and anything that does not decode is ignored. An expired name is dropped
    /// from the table so a stale address is never offered.
    fn record(&self, name: &str, peer: &Peer) {
        if !name::decodes(name) {
            tracing::trace!(name, "ignoring an mDNS instance that is not a bifrost name");
            return;
        }
        if peer.is_expiry() {
            self.expire(name);
            return;
        }
        let hints = shape(
            peer.addrs()
                .iter()
                .map(|(ip, port)| SocketAddr::new(*ip, *port)),
        );
        self.learn(name, hints);
    }

    /// Hold `hints` under `name` and wake the subscribers of the node it belongs to. The wake
    /// follows the write, so a woken subscription always re-reads a table that already includes it.
    ///
    /// A new name is tested once against each subscribed key, and the answer is kept: a
    /// re-announcement costs a map lookup.
    fn learn(&self, name: &str, hints: Vec<SocketAddr>) {
        let mut table = self.table();
        let heard = Instant::now();
        if let Some(entry) = table.peers.get_mut(name) {
            entry.hints = hints;
            entry.heard = heard;
            if let Some(node) = entry.node {
                table.wake(node);
            }
            return;
        }
        let node = table.resolve(name);
        if !table.make_room(node) {
            return;
        }
        if let Some(node) = node {
            tracing::debug!(node = %node.short(), count = hints.len(), "discovered peer over mDNS");
        }
        table
            .peers
            .insert(name.to_owned(), Entry { node, hints, heard });
        if let Some(node) = node {
            table.wake(node);
        }
    }

    /// Drop `name` from the table and wake the subscribers of the node it belonged to.
    ///
    /// Only that name goes: a node heard under a newer name keeps it, so a rotated-out name's
    /// goodbye never takes away what the fresh name already said.
    fn expire(&self, name: &str) {
        let mut table = self.table();
        if let Some(Entry {
            node: Some(node), ..
        }) = table.peers.remove(name)
        {
            table.wake(node);
        }
    }

    /// What is held for `node` right now, from the name it was most recently heard under; empty
    /// when nothing is.
    fn held(&self, node: NodeId) -> Vec<SocketAddr> {
        self.table()
            .peers
            .values()
            .filter(|entry| entry.node == Some(node))
            .max_by_key(|entry| entry.heard)
            .map(|entry| entry.hints.clone())
            .unwrap_or_default()
    }

    /// A wake receiver for `node`, created with the current state already seen.
    ///
    /// A new subscription tests the names held unmatched once against its key, so a node heard
    /// before anyone asked for it is found. Channels no subscription holds any more are pruned
    /// here, the one place entries are made, so the map never holds more than the live
    /// subscriptions plus the one being made.
    fn watch(&self, node: NodeId) -> watch::Receiver<()> {
        let mut table = self.table();
        let Table { peers, watchers } = &mut *table;
        watchers.retain(|_, watcher| watcher.wake.receiver_count() > 0);
        watchers
            .entry(node)
            .or_insert_with(|| {
                let names = Resolver::of(&node);
                for (name, entry) in peers.iter_mut() {
                    if entry.node.is_none() && names.matches(name) {
                        entry.node = Some(node);
                    }
                }
                Watcher {
                    wake: watch::channel(()).0,
                    names,
                }
            })
            .wake
            .subscribe()
    }
}

impl Table {
    fn wake(&self, node: NodeId) {
        if let Some(watcher) = self.watchers.get(&node) {
            watcher.wake.send_replace(());
        }
    }

    /// The live subscription `name` belongs to, if any. Tests against subscribed keys only, so a
    /// node that dials no one tests nothing.
    fn resolve(&self, name: &str) -> Option<NodeId> {
        self.watchers
            .iter()
            .filter(|(node, _)| self.is_live(**node))
            .find(|(_, watcher)| watcher.names.matches(name))
            .map(|(node, _)| *node)
    }

    /// Make room for a new name that belongs to `node`, or to no one; `false` when there is none.
    ///
    /// A node at [`MAX_NAMES_PER_NODE`] gives up its own oldest name. Otherwise, at [`MAX_PEERS`],
    /// the oldest name no live subscription is waiting on goes, so neither an on-LAN flood nor a key
    /// holder's minted names can push out a peer someone is waiting on. With every entry waited on,
    /// the new name is refused.
    fn make_room(&mut self, node: Option<NodeId>) -> bool {
        if let Some(node) = node {
            let own = self
                .peers
                .iter()
                .filter(|(_, entry)| entry.node == Some(node));
            if own.clone().count() >= MAX_NAMES_PER_NODE {
                let oldest = own
                    .min_by_key(|(_, entry)| entry.heard)
                    .map(|(name, _)| name.clone());
                return oldest.is_some_and(|name| self.peers.remove(&name).is_some());
            }
        }
        if self.peers.len() < MAX_PEERS {
            return true;
        }
        let oldest = self
            .peers
            .iter()
            .filter(|(_, entry)| !entry.node.is_some_and(|node| self.is_live(node)))
            .min_by_key(|(_, entry)| entry.heard)
            .map(|(name, _)| name.clone());
        oldest.is_some_and(|name| self.peers.remove(&name).is_some())
    }

    /// Whether someone is still subscribed to `node`.
    fn is_live(&self, node: NodeId) -> bool {
        self.watchers
            .get(&node)
            .is_some_and(|watcher| watcher.wake.receiver_count() > 0)
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
/// Only [`Spawn`](Self::Spawn) and [`Entropy`](Self::Entropy) stop the service: the rest name an
/// advertisement that could not be composed, which leaves the node browsing and is carried as the
/// cause of [`Advertising::BrowseOnly`].
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
    /// The system gave no randomness for the name to announce under. The service refuses to start
    /// rather than announce under a guessable name, and never falls back to the key.
    #[error("draw randomness for the mdns name")]
    Entropy(#[source] getrandom::Error),
}

#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod name_tests;
#[cfg(test)]
mod publish_tests;
