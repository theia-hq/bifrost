//! In-process implementation of the Bifrost transport interface.
//!
//! Sessions ride in-memory channels, not sockets. This exists for two reasons: it makes tests of
//! everything above the transport hermetic and instant, and it is the strongest anti-overfit check
//! on the interface. If a channels-only transport, iroh's QUIC, and a future raw-QUIC transport all pass
//! the same conformance suite, the interface is genuinely transport-agnostic and not iroh-shaped.
//!
//! Discovery is built in via a process-global registry keyed by [`NodeId`], so this is a
//! self-discovering transport: `connect` resolves the peer with no external `Discovery` object,
//! exactly as the design intends.

use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

use bifrost_core::CryptoKind;
pub use bifrost_core::NodeId;
use bifrost_transport::{Addr, Error};
pub use bifrost_transport::{Session, Transport};
use tokio::io;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

/// Buffer size for each in-memory stream, matching the wire's streaming chunk.
const CAP: usize = 64 * 1024;

/// One bidirectional stream, split into its writable and readable halves.
type Stream = (
    io::WriteHalf<io::DuplexStream>,
    io::ReadHalf<io::DuplexStream>,
);

/// Process-global directory of live endpoints: `NodeId` to its inbound-session sender.
static REGISTRY: LazyLock<Mutex<HashMap<NodeId, mpsc::UnboundedSender<MemSession>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Source of unique identities for bound endpoints.
static COUNTER: AtomicU64 = AtomicU64::new(1);

fn registry() -> MutexGuard<'static, HashMap<NodeId, mpsc::UnboundedSender<MemSession>>> {
    REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// An in-process endpoint. Reachable by other endpoints in the same process.
pub struct MemTransport {
    node: NodeId,
    inbound: AsyncMutex<mpsc::UnboundedReceiver<MemSession>>,
}

impl MemTransport {
    /// Bind a fresh in-process endpoint with a unique identity.
    pub fn bind() -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut key = [0u8; NodeId::KEY_LEN];
        key[..8].copy_from_slice(&seq.to_le_bytes());
        let node = NodeId::new(CryptoKind::Ed25519, key);

        let (tx, rx) = mpsc::unbounded_channel();
        registry().insert(node, tx);
        Self {
            node,
            inbound: AsyncMutex::new(rx),
        }
    }
}

impl Drop for MemTransport {
    fn drop(&mut self) {
        registry().remove(&self.node);
    }
}

impl Transport for MemTransport {
    type Session = MemSession;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(self.node)
    }

    async fn connect(&self, addr: Addr) -> Result<MemSession, Error> {
        let peer = registry()
            .get(&addr.node)
            .cloned()
            .ok_or_else(|| Error::Connect(Box::new(MemError::Unreachable)))?;

        // Two channels carry newly-opened streams, one per direction. The connector keeps its ends
        // and hands the acceptor the matching ends.
        let (dialer_opens, dialer_opened) = mpsc::unbounded_channel();
        let (accepter_opens, accepter_opened) = mpsc::unbounded_channel();

        let accepter = MemSession {
            peer: self.node,
            opens: accepter_opens,
            incoming: AsyncMutex::new(dialer_opened),
        };
        peer.send(accepter)
            .map_err(|_| Error::Connect(Box::new(MemError::Unreachable)))?;

        Ok(MemSession {
            peer: addr.node,
            opens: dialer_opens,
            incoming: AsyncMutex::new(accepter_opened),
        })
    }

    async fn accept(&self) -> Result<MemSession, Error> {
        let mut inbound = self.inbound.lock().await;
        inbound.recv().await.ok_or(Error::Closed)
    }

    async fn close(&self) {
        registry().remove(&self.node);
    }
}

/// An in-process session between two endpoints.
pub struct MemSession {
    peer: NodeId,
    opens: mpsc::UnboundedSender<Stream>,
    incoming: AsyncMutex<mpsc::UnboundedReceiver<Stream>>,
}

impl Session for MemSession {
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
        // Resolves when the peer drops its session: its `opens` sender closes, so our receiver ends.
        let mut incoming = self.incoming.lock().await;
        while incoming.recv().await.is_some() {}
    }
}

/// Why an in-process connection could not be made.
#[derive(Debug, thiserror::Error)]
enum MemError {
    /// No endpoint with that identity is bound in this process.
    #[error("peer not reachable in this process")]
    Unreachable,
}
