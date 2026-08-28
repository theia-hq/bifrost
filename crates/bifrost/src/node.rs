use bifrost_core::{Addr, Discovery, Error, NodeId};
use bifrost_transport::Transport;

/// A composed endpoint: a [`Transport`] paired with a [`Discovery`].
///
/// This is what applications hold. It makes discovery an explicit part of composition: you dial a
/// bare [`NodeId`], the discovery resolves hints, and the transport establishes the session. The app
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

    /// Dial a peer by identity: resolve hints via discovery, then establish a session.
    pub async fn connect(&self, node: NodeId) -> Result<T::Session, Error> {
        let hints = self.discovery.resolve(node).await?;
        self.transport.connect(Addr { node, hints }).await
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
