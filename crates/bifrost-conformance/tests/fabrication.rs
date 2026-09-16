//! Falsifiers for the identity cases: a fabricating transport must fail them.
//!
//! These tests pin the assertions that catch a transport whose attribution has no basis, never a
//! claim that the suite proves an honest one. The naive `Fabricator` reports a peer it was never
//! given; `ImpersonatorAtHint` answers a dial with the dialed key; `EchoLiar` carries bytes and
//! echoes identities with no handshake at all, so it shows the gap the claim-rejection case closes.
//! Each must panic where the assertion expects it, so the assertions are not vacuous. What the suite
//! still cannot catch (plaintext under `Sealed`, capture, tamper, replay) is named in the crate docs
//! and the transport's admission checklist.

use core::net::SocketAddr;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use bifrost::{Addr, Announced, CryptoKind, Error, NoDiscovery, Node, NodeId, Session, Transport};
use bifrost_conformance::{
    claimed_identity_not_attributed, identity_binding, reach_roundtrip, wrong_key_rejected,
};
use tokio::io;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

/// The identity the fabricated transport claims for itself.
fn claimed() -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [0x01; NodeId::KEY_LEN])
}

/// The identity the fabricated session attributes to the peer, which is never the key dialed.
fn attributed() -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [0x02; NodeId::KEY_LEN])
}

/// An identity held by a test double, distinct per byte so parallel tests never share a registry
/// key.
fn own(byte: u8) -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [byte; NodeId::KEY_LEN])
}

/// A transport that answers every dial with a session for a key nobody reached.
struct Fabricator;

impl Transport for Fabricator {
    type Security = Announced;
    type Session = FabricatedSession;

    fn node_id(&self) -> NodeId {
        claimed()
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(claimed())
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    async fn connect(&self, _addr: Addr) -> Result<FabricatedSession, Error> {
        Ok(FabricatedSession)
    }

    async fn accept(&self) -> Result<FabricatedSession, Error> {
        Ok(FabricatedSession)
    }

    async fn close(&self) {}
}

/// A session that reports an identity no handshake established.
struct FabricatedSession;

impl Session for FabricatedSession {
    type Security = Announced;
    type Write = io::Sink;
    type Read = io::Empty;

    fn peer(&self) -> NodeId {
        attributed()
    }

    async fn open_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn accept_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn wait_closed(&self) {}
}

/// A responder that answers every dial by claiming the key it was dialed under, without holding it.
///
/// This is the impersonator at an address hint: the dialed key looks consistent on the dial side,
/// because the liar echoes it, so attribution consistency alone cannot tell it from a proof.
struct ImpersonatorAtHint;

impl Transport for ImpersonatorAtHint {
    type Security = Announced;
    type Session = ImpersonatedSession;

    fn node_id(&self) -> NodeId {
        claimed()
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(claimed())
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    async fn connect(&self, addr: Addr) -> Result<ImpersonatedSession, Error> {
        Ok(ImpersonatedSession { peer: addr.node })
    }

    async fn accept(&self) -> Result<ImpersonatedSession, Error> {
        Ok(ImpersonatedSession { peer: claimed() })
    }

    async fn close(&self) {}
}

/// A session that speaks for the key that was dialed, with no key possession behind it.
struct ImpersonatedSession {
    peer: NodeId,
}

impl Session for ImpersonatedSession {
    type Security = Announced;
    type Write = io::Sink;
    type Read = io::Empty;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn accept_bi(&self) -> Result<(io::Sink, io::Empty), Error> {
        Ok((io::sink(), io::empty()))
    }

    async fn wait_closed(&self) {}
}

/// A process-global directory of live echo endpoints: the true node id to its inbound session.
static LIARS: LazyLock<Mutex<HashMap<NodeId, mpsc::UnboundedSender<EchoSession>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Buffer size for each in-memory stream, matching the other in-process transport.
const CAP: usize = 64 * 1024;

/// One bidirectional stream, split into its writable and readable halves.
type Stream = (
    io::WriteHalf<io::DuplexStream>,
    io::ReadHalf<io::DuplexStream>,
);

/// A byte-carrying transport that proves nothing: `connect` reports the key it dialed, `accept`
/// reports the identity the dialer claimed, and streams carry real bytes.
///
/// This is the smart liar the naive suite admits: it has a registry of endpoints, so it echoes the
/// keys it knows and refuses the ones it does not, passing both [`identity_binding`] and
/// [`wrong_key_rejected`]. [`claimed_identity_not_attributed`] is the assertion that catches it.
struct EchoLiar {
    node: NodeId,
    claim: NodeId,
    inbound: AsyncMutex<mpsc::UnboundedReceiver<EchoSession>>,
}

impl EchoLiar {
    /// Bind an echo endpoint with identity `node` that claims `claim` to whoever dials it.
    fn new(node: u8, claim: NodeId) -> Self {
        let node = own(node);
        let (tx, rx) = mpsc::unbounded_channel();
        LIARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(node, tx);
        Self {
            node,
            claim,
            inbound: AsyncMutex::new(rx),
        }
    }
}

impl Drop for EchoLiar {
    fn drop(&mut self) {
        LIARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.node);
    }
}

impl Transport for EchoLiar {
    type Security = Announced;
    type Session = EchoSession;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(self.node)
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    async fn connect(&self, addr: Addr) -> Result<EchoSession, Error> {
        let peer = LIARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&addr.node)
            .cloned()
            .ok_or_else(|| Error::Connect(Box::new(io::Error::other("no echo endpoint there"))))?;

        let (dialer_opens, dialer_opened) = mpsc::unbounded_channel();
        let (accepter_opens, accepter_opened) = mpsc::unbounded_channel();

        // The lie: the acceptor is handed the claimed identity with nothing behind it. The dial
        // side echoes the dialed key instead.
        let accepter = EchoSession {
            peer: self.claim,
            opens: accepter_opens,
            incoming: AsyncMutex::new(dialer_opened),
        };
        peer.send(accepter)
            .map_err(|_| Error::Connect(Box::new(io::Error::other("echo endpoint gone"))))?;

        Ok(EchoSession {
            peer: addr.node,
            opens: dialer_opens,
            incoming: AsyncMutex::new(accepter_opened),
        })
    }

    async fn accept(&self) -> Result<EchoSession, Error> {
        let mut inbound = self.inbound.lock().await;
        inbound.recv().await.ok_or(Error::Closed)
    }

    async fn close(&self) {
        LIARS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.node);
    }
}

/// An in-process session that carries bytes and attributes whatever identity it was handed.
struct EchoSession {
    peer: NodeId,
    opens: mpsc::UnboundedSender<Stream>,
    incoming: AsyncMutex<mpsc::UnboundedReceiver<Stream>>,
}

impl Session for EchoSession {
    type Security = Announced;
    type Write = io::WriteHalf<io::DuplexStream>;
    type Read = io::ReadHalf<io::DuplexStream>;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        let (near, far) = io::duplex(CAP);
        let (near_read, near_write) = io::split(near);
        let (far_read, far_write) = io::split(far);
        self.opens
            .send((far_write, far_read))
            .map_err(|_| Error::Closed)?;
        Ok((near_write, near_read))
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        let mut incoming = self.incoming.lock().await;
        incoming.recv().await.ok_or(Error::Closed)
    }

    async fn wait_closed(&self) {
        let mut incoming = self.incoming.lock().await;
        while incoming.recv().await.is_some() {}
    }
}

/// A session that speaks for a key the dialer never asked for fails [`identity_binding`].
#[tokio::test]
#[should_panic(expected = "the dialer attributes the key it dialed")]
async fn fabricated_peer_fails_identity_binding() {
    identity_binding(Fabricator, Fabricator).await;
}

/// A transport that accepts every key fails [`wrong_key_rejected`], the case a naive announced-key
/// wrapper passes today.
#[tokio::test]
#[should_panic(expected = "identity that was never reached")]
async fn session_for_wrong_key_fails_wrong_key_rejection() {
    let fabricated = NodeId::new(CryptoKind::Ed25519, [0x03; NodeId::KEY_LEN]);
    wrong_key_rejected(Fabricator, Fabricator, fabricated).await;
}

/// A responder that claims the dialed key without holding it fails [`wrong_key_rejected`]: the dial
/// yields a session for an identity that was never reached.
#[tokio::test]
#[should_panic(expected = "identity that was never reached")]
async fn impersonator_at_hint_fails_wrong_key_rejection() {
    let fabricated = NodeId::new(CryptoKind::Ed25519, [0x04; NodeId::KEY_LEN]);
    wrong_key_rejected(ImpersonatorAtHint, ImpersonatorAtHint, fabricated).await;
}

/// A byte-carrying transport that echoes identities and proves nothing passes the naive identity
/// cases: parity, attribution consistency, and wrong-key refusal.
///
/// This pins the limit the claim-rejection case closes. The next test shows
/// [`claimed_identity_not_attributed`] catching the same liar.
#[tokio::test]
async fn echo_liar_passes_the_naive_identity_cases() {
    let receiver = EchoLiar::new(0x20, own(0x20));
    let sender = Node::new(EchoLiar::new(0x21, own(0x21)), NoDiscovery);
    reach_roundtrip(sender, receiver).await;

    identity_binding(
        EchoLiar::new(0x22, own(0x22)),
        EchoLiar::new(0x23, own(0x23)),
    )
    .await;

    wrong_key_rejected(
        EchoLiar::new(0x24, own(0x24)),
        EchoLiar::new(0x25, own(0x25)),
        own(0x26),
    )
    .await;
}

/// A dialer claiming a foreign identity must never be attributed it, so the echo liar fails
/// [`claimed_identity_not_attributed`] even though the naive identity cases pass it.
#[tokio::test]
#[should_panic(expected = "the acceptor attributed an identity the dialer never proved")]
async fn echo_liar_fails_claimed_identity_rejection() {
    let claimed = own(0x30);
    claimed_identity_not_attributed(
        EchoLiar::new(0x31, claimed),
        EchoLiar::new(0x32, claimed),
        claimed,
    )
    .await;
}
