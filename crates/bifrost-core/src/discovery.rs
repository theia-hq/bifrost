use core::net::SocketAddr;
use std::collections::HashMap;

use crate::{AddrUpdate, HintStream, NodeId};

mod union;

use union::Union;

/// Tells a dial where a [`NodeId`] can be reached, as a feed of address hints for that one node.
///
/// Orthogonal to the transport: discovery PRODUCES hints, a transport CONSUMES them (see
/// `Transport::connect_with_updates` in `bifrost-transport`). A self-discovering transport (iroh,
/// mem) pairs with [`NoDiscovery`]; a transport with no built-in discovery (raw QUIC) pairs with a
/// real source ([`StaticDiscovery`], mDNS, later pkarr). Sources compose: [`Layered`] subscribes to
/// two together and unions their hints, so an explicit and a learned source can both feed one dial.
///
/// A subscription is the only way to ask, because a snapshot is just its first answer: the first
/// [`Hints`](AddrUpdate::Hints), or [`Settled`](AddrUpdate::Settled) when there is nothing.
/// It is keyed by one node and there is no way to list what a source holds, so discovery answers
/// "where is this key" and never "who is out there".
///
/// # Implementing a source
///
/// These are the obligations a dial relies on. The compiler checks none of them; the conformance
/// doubles are the template.
///
/// - `subscribe` starts no task and does no I/O. It returns a view over state the source already
///   keeps, driven entirely by its consumer's polls, and dropping it stops anything pending.
/// - The feed is state-shaped: each item is what the source holds now, and a slow consumer sees the
///   latest state rather than a queue of every change, so a flood of updates costs re-reads, never
///   memory.
/// - The feed yields only on a change, and is otherwise `Pending`: a feed that is ready on every
///   poll never lets its consumer see it settle. [`Layered`] bounds how much of one it takes per
///   poll, but still holds its answer while the feed keeps yielding.
/// - Wakeups are per node: a change to one node never wakes a subscription for another.
/// - Nothing a feed yields may cause a dial or cancel one. It answers; the consumer decides.
/// - [`Removed`](AddrUpdate::Removed) only follows a [`Hints`](AddrUpdate::Hints), and
///   [`Settled`](AddrUpdate::Settled) is said at most once, before anything else.
/// - A source that will never say more ends its feed rather than leaving it pending.
pub trait Discovery {
    /// Subscribe to address updates for one node. The source is caller-bounded: nothing here dials,
    /// and nothing here waits, so the consumer that polls owns every deadline.
    fn subscribe(&self, node: NodeId) -> HintStream;
}

/// Discovery for transports that resolve internally (iroh, mem): every feed has already ended.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDiscovery;

impl Discovery for NoDiscovery {
    fn subscribe(&self, _node: NodeId) -> HintStream {
        HintStream::ended()
    }
}

/// Discovery from a fixed in-memory table. The reference source for tests and static deployments.
#[derive(Debug, Clone, Default)]
pub struct StaticDiscovery {
    table: HashMap<NodeId, Vec<SocketAddr>>,
}

impl StaticDiscovery {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the direct addresses for an identity.
    pub fn insert(&mut self, node: NodeId, addrs: Vec<SocketAddr>) {
        self.table.insert(node, addrs);
    }
}

impl Discovery for StaticDiscovery {
    /// Answers once, then ends: the table cannot change behind `&self`, so there is never more to
    /// say. An entry answers with its hints; a missing (or empty) one settles at once, which is how
    /// a table says it is ready by construction.
    fn subscribe(&self, node: NodeId) -> HintStream {
        match self.table.get(&node) {
            Some(hints) if !hints.is_empty() => HintStream::once(AddrUpdate::Hints(hints.clone())),
            _ => HintStream::once(AddrUpdate::Settled),
        }
    }
}

/// Two discovery sources subscribed together, their hints unioned (duplicates removed).
///
/// This is how an app composes an explicit source with a learned one: a [`StaticDiscovery`] of hand-
/// fed direct address hints layered over a network source (mDNS), so a dial reaches a peer whether it
/// was supplied explicitly, heard on the LAN, or both. A source that finds nothing contributes
/// nothing, so an empty union means "let the transport try", exactly as a bare source would.
///
/// The union is kept per source: a [`Removed`](AddrUpdate::Removed) from one source withdraws only
/// that source's hints, so a forged LAN expiry can never erase an address the user supplied.
///
/// A source that fails counts as one that ended, its last hints kept, so the other source still
/// serves the dial. When every source has stopped with no hint held and one of them failed, the
/// merged feed yields that failure (the primary's first) and ends, so the dial fails for a reason
/// rather than going ahead with nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Layered<P, S> {
    /// The primary source; its hints lead the unioned result.
    primary: P,
    /// The secondary source; its hints follow, minus any the primary already yielded.
    secondary: S,
}

impl<P: Discovery, S: Discovery> Layered<P, S> {
    /// Layer a primary discovery source over a secondary one.
    pub fn new(primary: P, secondary: S) -> Self {
        Self { primary, secondary }
    }
}

impl<P: Discovery, S: Discovery> Discovery for Layered<P, S> {
    /// The merged feed holds its first answer until one source has a hit or every source has
    /// answered, so a fixed table that settles at once never cuts short a learned source that is
    /// still looking.
    fn subscribe(&self, node: NodeId) -> HintStream {
        HintStream::new(Union::new(
            self.primary.subscribe(node),
            self.secondary.subscribe(node),
        ))
    }
}
