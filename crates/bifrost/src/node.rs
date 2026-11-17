use core::net::SocketAddr;

use bifrost_core::{Addr, AddrUpdate, Discovery, Error, HintStream, Layered, NodeId};
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
    /// deadline; wrap this call in one. A transport may bound its own attempt too, but none waits on
    /// discovery alone.
    pub async fn connect(&self, node: NodeId) -> Result<T::Session, Error> {
        self.transport
            .connect_with_updates(Addr::from_node(node), self.discovery.subscribe(node))
            .await
    }

    /// Dial a peer by identity, trying `hints` first and then what the node's discovery finds.
    ///
    /// The hints go into this call's feed only: nothing is stored on the node, so no other dial's
    /// feed, running alongside or later, holds them. The transport may still keep addresses it was
    /// given for a peer while it keeps state for that peer, and try them in a later dial to it; see
    /// [`Transport::connect`]. The transport gets them at once, so a transport that does not
    /// wait for discovery still dials with them. Order and repeats reach the transport as given, and
    /// what it keeps of them is its own choice; this method does not limit how many you pass. The
    /// peer's identity is checked exactly as in [`connect`](Self::connect), so an address only
    /// chooses where the dial goes. With no hints this is `connect`, including its single attempt and
    /// the caller's deadline.
    pub async fn connect_hinted(
        &self,
        node: NodeId,
        hints: &[SocketAddr],
    ) -> Result<T::Session, Error> {
        // No hints is a plain dial by construction, not by how the union treats an empty source.
        if hints.is_empty() {
            return self.connect(node).await;
        }
        // The call's hints are the primary of a union scoped to this one subscription: the union
        // keeps the primary's list whole and in order, and says it on its first poll, before the
        // discovery behind it has answered. Built per call and dropped with the feed, so the
        // node itself holds nothing a second dial could read.
        let feed = Layered::new(Given(hints), Borrowed(&self.discovery)).subscribe(node);
        self.transport
            .connect_with_updates(Addr::from_node(node), feed)
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

/// One dial's addresses, as a source that answers once with them and ends.
///
/// Built for one subscription, so it ignores the node it is asked about. Never empty: a hint set is
/// non-empty when present, and `connect_hinted` takes the plain path when there are none. Borrows
/// the caller's addresses, so the one copy is the one the feed must own.
struct Given<'a>(&'a [SocketAddr]);

impl Discovery for Given<'_> {
    fn subscribe(&self, _node: NodeId) -> HintStream {
        HintStream::once(AddrUpdate::Hints(self.0.to_vec()))
    }
}

/// The node's discovery, borrowed for one subscription: the feed owns what it reads, so the borrow
/// ends with the `subscribe` call.
struct Borrowed<'a, D>(&'a D);

impl<D: Discovery> Discovery for Borrowed<'_, D> {
    fn subscribe(&self, node: NodeId) -> HintStream {
        self.0.subscribe(node)
    }
}
