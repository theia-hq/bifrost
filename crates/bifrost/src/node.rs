use core::time::Duration;

use bifrost_core::{Addr, Discovery, Error, NodeId};
use bifrost_transport::Transport;

/// How long a dial waits for discovery readiness before treating an empty resolve as final.
///
/// A background source (mDNS) sends its first query on its cadence, about a second after
/// construction, so a resolve in the first milliseconds misses a peer that is on the network. This
/// covers one query-response cycle with margin; a source that answers sooner ends the wait early.
const DISCOVERY_READY_TIMEOUT: Duration = Duration::from_millis(1500);

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
    ///
    /// An empty resolve is not final. Before concluding that nothing is known, the dial waits a
    /// bounded span for the discovery to become ready FOR THIS PEER and resolves once more, so a
    /// background source that has not heard the target yet still gets its chance. A resolve that
    /// already yielded hints dials at once, and a source with nothing to wait for returns
    /// immediately.
    pub async fn connect(&self, node: NodeId) -> Result<T::Session, Error> {
        let mut hints = self.discovery.resolve(node).await?;
        if hints.is_empty() {
            self.discovery
                .wait_ready(node, DISCOVERY_READY_TIMEOUT)
                .await;
            hints = self.discovery.resolve(node).await?;
        }
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
