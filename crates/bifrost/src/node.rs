use core::net::SocketAddr;

use bifrost_core::{Addr, Discovery, Error, NodeId};
use bifrost_transport::Transport;

/// A composed endpoint: a [`Transport`] paired with a [`Discovery`].
///
/// This is what applications hold. It makes discovery an explicit part of composition: you dial a
/// bare [`NodeId`], the discovery feeds hints, and the transport establishes the session. The app
/// never touches a concrete transport type beyond constructing this once.
pub struct Node<T, D> {
    transport: T,
    discovery: D,
}

impl<T: Transport, D: Discovery> Node<T, D> {
    /// Compose a transport with a discovery mechanism.
    pub fn new(transport: T, discovery: D) -> Self {
        Self {
            transport,
            discovery,
        }
    }

    /// This endpoint's identity.
    pub fn node_id(&self) -> NodeId {
        self.transport.node_id()
    }

    /// A directly-dialable address for this endpoint.
    pub fn local_addr(&self) -> Addr {
        self.transport.local_addr()
    }

    /// The sockets this endpoint's transport is bound to, exactly as bound.
    ///
    /// Bind truth, not an address book: an unspecified IP (`0.0.0.0`, `[::]`) comes back as bound.
    /// It is here because [`local_addr`](Self::local_addr) cannot stand in for it (its hints rewrite
    /// a wildcard to loopback, many-to-one), so a holder of a composed node that has to turn the
    /// bind into the addresses it answers on has nowhere else to read it from.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.transport.bound_sockets()
    }

    /// Dial a peer by identity: subscribe to discovery for it, and hand the feed to the transport.
    ///
    /// One dial, no retry, and no timer of its own: the transport reads the feed as its bind allows
    /// (a self-discovering bind dials at once, a direct-only one waits for the first answer) and the
    /// feed dies with the attempt. How long a silent source may hold the dial is the caller's
    /// deadline; wrap this call in one. A transport may bound its own attempt too (a sealed
    /// wrapper's deadline covers its dial, discovery included), but none waits on discovery alone.
    pub async fn connect(&self, node: NodeId) -> Result<T::Session, Error> {
        self.transport
            .connect_with_updates(Addr::from_node(node), self.discovery.subscribe(node))
            .await
    }

    /// Accept the next inbound session.
    pub async fn accept(&self) -> Result<T::Session, Error> {
        self.transport.accept().await
    }

    /// Gracefully close, draining buffered data first.
    pub async fn close(&self) {
        self.transport.close().await;
    }
}
