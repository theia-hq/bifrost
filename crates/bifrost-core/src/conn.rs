use core::net::SocketAddr;
use core::time::Duration;

/// How a session's bytes reach the peer: peer to peer, bounced off a relay, or both.
///
/// This answers the single most reassuring question a p2p tool can: "am I actually direct, or bouncing
/// off a relay?" A transport that tracks NAT traversal (iroh) reports it honestly, and it can change
/// over a session's life: a connection often starts [`Relayed`](Self::Relayed) and upgrades to
/// [`Direct`](Self::Direct) as hole-punching completes, so a reader should treat it as the CURRENT
/// path, not a fixed property. A transport that cannot tell reports [`Unknown`](Self::Unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Path {
    /// Peer to peer: bytes flow straight to the remote address, no relay in the middle.
    Direct,
    /// Bounced off a relay: no direct path is (yet) established.
    Relayed,
    /// Both a direct and a relayed path are open at once (an upgrade in progress, or multipath).
    Mixed,
    /// The transport does not expose its path (in-process, or not yet instrumented).
    #[default]
    Unknown,
}

/// A best-effort snapshot of how a session reaches its peer, for diagnostics like `swoosh status`.
///
/// Best-effort by design: every field a transport cannot determine is absent (the [`Path`] is
/// [`Unknown`](Path::Unknown), the rest are `None`), so this never fabricates a reassuring answer it
/// cannot back. It is a cheap, synchronous accessor snapshotting current state, deliberately OFF the
/// async hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnInfo {
    /// Whether the current path is direct, relayed, mixed, or unknown.
    pub path: Path,
    /// The transport's current round-trip estimate, if it tracks one.
    pub rtt: Option<Duration>,
    /// The remote address the current path reaches, if the transport exposes it.
    pub remote: Option<SocketAddr>,
}
