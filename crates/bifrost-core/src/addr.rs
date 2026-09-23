use core::net::SocketAddr;

use crate::{AddrUpdate, Error, NodeId};

/// How to reach a peer: its identity, plus optional direct-address hints.
///
/// A bare identity (no hints) is dialed via discovery. Hints let a caller reach a peer directly,
/// bypassing discovery, which is how local and hermetic connections work. This replaces any
/// transport-specific ticket: the rest of Bifrost speaks only [`NodeId`] and hints.
#[derive(Debug, Clone)]
pub struct Addr {
    /// The peer's identity.
    pub node: NodeId,
    /// Direct address hints, tried alongside or instead of discovery.
    pub hints: Vec<SocketAddr>,
}

impl Addr {
    /// An address carrying only an identity, to be resolved by discovery.
    pub fn from_node(node: NodeId) -> Self {
        Self {
            node,
            hints: Vec::new(),
        }
    }

    /// Fold a feed's first observation into this address: the one read of discovery a dial makes.
    ///
    /// [`Hints`](AddrUpdate::Hints) replaces the hints this address carried. [`Removed`], [`Settled`],
    /// or nothing at all leave it as it is, so the transport tries with what the caller held. An error
    /// fails the dial, as a failed lookup always has.
    ///
    /// [`Removed`]: AddrUpdate::Removed
    /// [`Settled`]: AddrUpdate::Settled
    pub fn seeded(self, first: Option<Result<AddrUpdate, Error>>) -> Result<Self, Error> {
        match first {
            Some(Ok(AddrUpdate::Hints(hints))) if !hints.is_empty() => Ok(Self {
                node: self.node,
                hints,
            }),
            Some(Err(err)) => Err(err),
            _ => Ok(self),
        }
    }
}

impl From<NodeId> for Addr {
    fn from(node: NodeId) -> Self {
        Self::from_node(node)
    }
}
