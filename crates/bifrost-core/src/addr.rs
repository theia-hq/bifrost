use core::net::SocketAddr;

use crate::NodeId;

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
}

impl From<NodeId> for Addr {
    fn from(node: NodeId) -> Self {
        Self::from_node(node)
    }
}
