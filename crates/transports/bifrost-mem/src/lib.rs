//! In-process implementation of the Bifrost transport interface.
//!
//! Sessions ride in-memory channels, not sockets. This exists for two reasons: it makes tests of
//! everything above the transport hermetic and instant, and it is the strongest anti-overfit check
//! on the interface. A channels-only transport, iroh's QUIC, and the raw-QUIC backend all pass the
//! same conformance suite, so the interface is genuinely transport-agnostic and not iroh-shaped.
//!
//! Discovery is built in via a process-global registry keyed by [`NodeId`], so this is a
//! self-discovering transport: `connect` finds the peer with no external `Discovery` object,
//! exactly as the design intends.

use core::net::SocketAddr;
use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

pub use bifrost_core::NodeId;
use bifrost_core::{Addr, Error, HintStream};
pub use bifrost_transport::{InProcess, Session, Transport};
use tokio::io;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

mod stream;

pub use crate::stream::{MemRead, MemWrite};
use crate::stream::{Severance, halves};

/// Buffer size for each in-memory stream, matching the wire's streaming chunk.
const CAP: usize = 64 * 1024;

/// One bidirectional stream, split into its writable and readable halves.
type Stream = (MemWrite, MemRead);

/// Process-global directory of live endpoints: `NodeId` to its inbound-session sender.
static REGISTRY: LazyLock<Mutex<HashMap<NodeId, mpsc::UnboundedSender<MemSession>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Source of unique identity seeds for bound endpoints.
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
    /// Bind a fresh in-process endpoint under a unique identity.
    ///
    /// The identity's secret comes from a process-wide counter, so anyone can compute it: this transport
    /// is for tests.
    pub fn bind() -> Self {
        Self::bind_with_secret(seed_for(COUNTER.fetch_add(1, Ordering::Relaxed)))
    }

    /// Bind under the identity `secret` derives. Private: the counter is what keeps one endpoint per
    /// identity, and a caller-chosen secret bound twice would replace the first endpoint's registration.
    fn bind_with_secret(secret: [u8; NodeId::KEY_LEN]) -> Self {
        let node = NodeId::from_ed25519_secret(&secret);
        let (tx, rx) = mpsc::unbounded_channel();
        registry().insert(node, tx);
        Self {
            node,
            inbound: AsyncMutex::new(rx),
        }
    }
}

/// The ed25519 seed a counter value names.
fn seed_for(seq: u64) -> [u8; NodeId::KEY_LEN] {
    let mut seed = [0u8; NodeId::KEY_LEN];
    seed[..8].copy_from_slice(&seq.to_le_bytes());
    seed
}

impl Drop for MemTransport {
    fn drop(&mut self) {
        registry().remove(&self.node);
    }
}

impl Transport for MemTransport {
    type Security = InProcess;
    type Session = MemSession;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        Addr::from_node(self.node)
    }

    /// None: an in-process transport binds no socket, so there is no bind truth to report and
    /// nothing about it is publishable on a network.
    fn bound_sockets(&self) -> Vec<SocketAddr> {
        Vec::new()
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

        // One close signal for the pair: either side closing ends every stream on both.
        let severance = Arc::new(Severance::default());
        let accepter = MemSession {
            peer: self.node,
            opens: accepter_opens,
            incoming: AsyncMutex::new(dialer_opened),
            severance: Arc::clone(&severance),
        };
        peer.send(accepter)
            .map_err(|_| Error::Connect(Box::new(MemError::Unreachable)))?;

        Ok(MemSession {
            peer: addr.node,
            opens: dialer_opens,
            incoming: AsyncMutex::new(accepter_opened),
            severance,
        })
    }

    /// Dials at once and never reads the feed: the in-process registry is how mem finds a peer, so
    /// no hint could change where this dial goes and waiting for one would only add latency.
    async fn connect_with_updates(
        &self,
        addr: Addr,
        _updates: HintStream,
    ) -> Result<MemSession, Error> {
        self.connect(addr).await
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
    /// Shared with the peer's session: set by either side's [`close`](Session::close).
    severance: Arc<Severance>,
}

impl Session for MemSession {
    type Security = InProcess;
    type Write = MemWrite;
    type Read = MemRead;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        if self.severance.is_severed() {
            return Err(Error::Closed);
        }
        let (near, far) = io::duplex(CAP);
        self.opens
            .send(halves(far, &self.severance))
            .map_err(|_| Error::Closed)?;
        Ok(halves(near, &self.severance))
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        let mut incoming = self.incoming.lock().await;
        tokio::select! {
            biased;
            () = self.severance.severed() => Err(Error::Closed),
            stream = incoming.recv() => stream.ok_or(Error::Closed),
        }
    }

    async fn wait_closed(&self) {
        // Resolves when the peer drops its session (its `opens` sender closes, so our receiver ends),
        // or when either side closes the pair.
        let mut incoming = self.incoming.lock().await;
        tokio::select! {
            () = self.severance.severed() => {}
            () = async { while incoming.recv().await.is_some() {} } => {}
        }
    }

    /// Sever the pair: every stream either side handed out now errors, never reads a clean end, and
    /// both sides' `wait_closed` resolve. There is no wire, so the peer learns at once.
    fn close(&self) {
        self.severance.sever();
    }
}

/// Why an in-process connection could not be made.
#[derive(Debug, thiserror::Error)]
enum MemError {
    /// No endpoint with that identity is bound in this process.
    #[error("peer not reachable in this process")]
    Unreachable,
}

#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod tests {
    use bifrost_transport::SecurityProfile as _;

    use super::{InProcess, MemTransport, Transport};

    /// The declared profile is PINNED per backend: every consumer's trust decision rests on it, so an
    /// accidental flip fails HERE, in the crate that declares it, rather than downstream in code that went
    /// on believing the old promise. `InProcess` is the profile the `bifrost-mem` entry in
    /// `scripts/sealed-gate.sh` authorizes (test-only backend, no wire).
    #[test]
    fn the_declared_profile_is_pinned_to_in_process() {
        assert_eq!(
            <MemTransport as Transport>::Security::SECURITY,
            InProcess::SECURITY
        );
    }
}
