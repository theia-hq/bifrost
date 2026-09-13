//! The Bifrost transport interface.
//!
//! A [`Transport`] moves bytes to a peer identified by its [`NodeId`]. Every transport declares what
//! it proves and protects as a [`SecurityProfile`]: [`Sealed`] (a handshake proves the peer holds
//! the `NodeId` key, and the channel is end-to-end AEAD), [`Announced`] (the peer key is
//! self-announced over a plaintext channel), or [`InProcess`] (no wire; the process boundary is the
//! trust boundary). The declaration is required and has no default, so a new backend cannot compile
//! without stating what it provides.
//!
//! The declaration is a claim, not a proof. A consumer that carries authority bounds on
//! [`PeerProven`] or [`Secure`] and reads [`SecurityProfile::SECURITY`] at a runtime seam; the
//! conformance suite proves byte movement and identity binding, not the channel. The [`Security`]
//! value and the marker types state what each profile means and what is left to protocol review.
//!
//! This is the pluggable boundary: iroh today, a raw-QUIC transport next, others later, all exposing
//! the same byte-stream interface and all held to the same behaviour by the conformance suite.
//! Everything above this boundary (the wire, the products) is transport-blind.
//!
//! This crate is the byte-moving interface and nothing else: implement [`Transport`] + [`Session`] to
//! add a transport. The transport-neutral vocabulary it speaks ([`Addr`], [`Error`], [`ConnInfo`],
//! [`Path`], and the [`Discovery`](bifrost_core::Discovery) contract) lives in `bifrost-core`.
//!
//! Streams are exposed as associated types bounded by [`AsyncRead`]/[`AsyncWrite`], so the boundary
//! is a plain byte-stream interface with no boxing: a transport differs only in how a session is
//! established, never in how bytes flow once it is.

pub use bifrost_core::{Addr, ConnInfo, Error, NodeId, NodeIdParseError, Path};
use tokio::io;

mod security;
pub use security::{
    Announced, ChannelProtection, Confidential, InProcess, PeerProof, PeerProven, Sealed, Secure,
    Security, SecurityProfile,
};

// `async fn` in these traits is deliberate. The returned futures are not `Send`-bounded, which is
// fine here: callers drive sessions with structured concurrency (join/select on one task), not
// `tokio::spawn` across threads. If a future consumer must spawn sessions onto other threads,
// revisit with `trait_variant` or an explicit `-> impl Future + Send`. See DECISIONS.
/// A pluggable transport: binds a local identity and moves [`Session`]s to and from peers.
///
/// Every transport declares a [`SecurityProfile`]; the profile is required, so a new backend cannot
/// compile without stating what it provides. The session type must carry the same profile, which the
/// compiler enforces through the [`Session::Security`] equality below.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// The security profile every session of this transport carries. Required, no default.
    type Security: SecurityProfile;

    /// The session type this transport establishes. Its profile is the transport's, so a function
    /// that only sees a session still knows what the transport declared.
    type Session: Session<Security = Self::Security>;

    /// This transport's local identity.
    fn node_id(&self) -> NodeId;

    /// A directly-dialable address for this transport (identity plus local hints).
    fn local_addr(&self) -> Addr;

    /// Dial a peer.
    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error>;

    /// Accept the next inbound session.
    async fn accept(&self) -> Result<Self::Session, Error>;

    /// Gracefully close, draining buffered data so in-flight bytes are delivered first.
    async fn close(&self);
}

/// A session with a peer.
///
/// This trait moves bytes. What the session proves about the peer and protects on the wire is the
/// transport's declared [`SecurityProfile`], mirrored here as [`Self::Security`] so the requirement
/// travels with every value the transport hands up.
#[allow(async_fn_in_trait)]
pub trait Session {
    /// The security profile this session's transport declared.
    type Security: SecurityProfile;

    /// The writable half of a stream to the peer.
    type Write: io::AsyncWrite + Unpin + Send;
    /// The readable half of a stream from the peer.
    type Read: io::AsyncRead + Unpin + Send;

    /// The peer's identity, as this session's transport attributes it.
    ///
    /// The strength of the attribution is declared by [`Self::Security`]: proven, announced, or
    /// exact by construction. This accessor reports the attribution; the profile says how far it can
    /// be trusted.
    fn peer(&self) -> NodeId;

    /// Open a bidirectional stream to the peer.
    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error>;

    /// Accept the next bidirectional stream from the peer.
    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error>;

    /// Wait until the peer closes the session, keeping it alive so final bytes are delivered.
    async fn wait_closed(&self);

    /// A best-effort snapshot of how this session reaches the peer (direct vs relayed, rtt, remote).
    ///
    /// Additive and optional: the default returns [`Path::Unknown`] with no rtt or remote, so a
    /// transport that cannot tell (or has not been instrumented) compiles and behaves unchanged. A
    /// transport that tracks the path overrides this. A cheap synchronous accessor, not part of the
    /// byte-moving hot path.
    fn conn_info(&self) -> ConnInfo {
        ConnInfo::default()
    }
}

#[cfg(test)]
mod security_tests;
