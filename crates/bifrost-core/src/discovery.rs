use core::net::SocketAddr;
use core::time::Duration;
use std::collections::HashMap;
use std::time::Instant;

use crate::{Error, NodeId};

/// Resolves a [`NodeId`] to reachable address hints.
///
/// Orthogonal to the transport: discovery PRODUCES hints, a transport CONSUMES them via
/// [`Addr`](crate::Addr). A self-discovering transport (iroh, mem) pairs with [`NoDiscovery`]; a
/// transport with no built-in discovery (raw QUIC) pairs with a real resolver ([`StaticDiscovery`],
/// mDNS, later pkarr). Sources compose: [`Layered`] tries two together and unions their hints, so an
/// explicit and a learned source can both feed one dial.
#[allow(async_fn_in_trait)]
pub trait Discovery {
    /// Resolve an identity to address hints. An empty result means "no hints, let the transport try".
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error>;

    /// Wait until this source can be expected to answer, bounded by `timeout`.
    ///
    /// A source that learns hints in the background (mDNS) may not have completed its first cycle
    /// when a dial resolves immediately after construction, so an empty resolve can be a timing
    /// artifact rather than a real absence. A dial that resolved empty calls this before treating
    /// the result as final, then resolves once more. An implementation returns as soon as it can
    /// answer, so a source with something to give does not pay the whole bound; the default is a
    /// no-op, since a fixed table or a transport-internal resolver is ready by construction.
    async fn wait_ready(&self, timeout: Duration) {
        let _ = timeout;
    }
}

/// Discovery for transports that resolve internally (iroh, mem): yields no external hints.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDiscovery;

impl Discovery for NoDiscovery {
    async fn resolve(&self, _node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        Ok(Vec::new())
    }
}

/// Discovery from a fixed in-memory table. The reference resolver for tests and static deployments.
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
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        Ok(self.table.get(&node).cloned().unwrap_or_default())
    }
}

/// Two discovery sources tried together, their hints unioned (duplicates removed).
///
/// This is how an app composes an explicit source with a learned one: a [`StaticDiscovery`] of hand-
/// fed direct address hints layered over a network resolver (mDNS), so a dial reaches a peer whether it
/// was supplied explicitly, heard on the LAN, or both. A source that finds nothing contributes
/// nothing, so an empty union means "let the transport try", exactly as a bare source would.
#[derive(Debug, Clone, Copy, Default)]
pub struct Layered<P, S> {
    /// The primary source, tried first; its hints lead the unioned result.
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
    async fn resolve(&self, node: NodeId) -> Result<Vec<SocketAddr>, Error> {
        let mut hints = self.primary.resolve(node).await?;
        for addr in self.secondary.resolve(node).await? {
            if !hints.contains(&addr) {
                hints.push(addr);
            }
        }
        Ok(hints)
    }

    /// Both sources wait, in resolve order, sharing the caller's bound: a source that answers at
    /// once (the default, a fixed table) consumes none of it, so the common static-over-learned
    /// composition spends the whole bound on the learned source.
    async fn wait_ready(&self, timeout: Duration) {
        let start = Instant::now();
        self.primary.wait_ready(timeout).await;
        self.secondary
            .wait_ready(timeout.saturating_sub(start.elapsed()))
            .await;
    }
}
