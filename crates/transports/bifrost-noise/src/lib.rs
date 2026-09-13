//! Sealed wrapper over any byte-moving transport.
//!
//! [`Noise<T>`] runs a `Noise_XX_25519_ChaChaPoly_SHA256` handshake over one stream of an inner
//! [`Transport`], proves the peer holds the private key for the [`NodeId`] it was reached under,
//! and re-exposes the result as logical streams. Every byte after the handshake is a Noise message;
//! the inner transport moves bytes, and nothing it announces or declares is trusted, including a
//! `Sealed` declaration.
//!
//! This is the upgrade path for a transport whose channel is plaintext or whose peer key is
//! self-announced: wrap it once and every consumer above sees `Sealed`. The wrapper never consults
//! `inner.peer()` for a decision, so an inner that announces an unrelated link identity (a device
//! key that is not the `NodeId`) still wraps correctly.
//!
//! # The profile arithmetic
//!
//! The wrapper declares `Sealed` for every inner it accepts ([`Wrappable`]):
//!
//! | inner | wrapper | note |
//! | --- | --- | --- |
//! | `Announced` | `Sealed` | the upgrade case: plaintext underlay inside the Noise channel |
//! | `Sealed` | `Sealed` | allowed and redundant: sealed twice, one extra handshake and round trip |
//! | `InProcess` | refused | an in-process identity is not a key, so there is no seed to prove |
//!
//! Wrapping a `Sealed` inner is not prevented. It costs a second independent handshake and AEAD over
//! bytes that are already sealed, and it earns its keep only where a policy wants every session to
//! pass through one reviewed handshake regardless of the underlay, or where the wrapper is being
//! exercised over a real network stack. It is never a reason to skip the wrapper's own handshake:
//! the handshake is unconditional, and the profile is a constant on the type, not a projection of
//! the inner's declaration.
//!
//! # Wire
//!
//! The frozen v0 spelling is [`wire`]. Both sides write the [`TAG`](wire::TAG), then run XX. Each
//! side generates a fresh X25519 static per handshake and signs `CTX_role || h_prev || S_own` under
//! its ed25519 identity, where `h_prev` is Noise's running handshake hash at the signer's point
//! (after message one for the responder, after message two for the initiator). The signature rides
//! in the encrypted payload as `NodeId || sig` in messages two and three.
//!
//! The accept side proves the peer at one point: after message three decrypts and
//! `verify_strict(claimed, CTX_INITIATOR || h2 || S_i, sig)` passes, where `h2` is the hash captured
//! after message two was written and `S_i` is the static read back from the handshake state. No
//! session exists before that. The dial side verifies the responder's signature under the dialed
//! [`NodeId`] before writing message three, and refuses a claimed signer that differs.
//!
//! # Bounds, streams, and interop
//!
//! `connect` and `accept` take the inner's first stream and complete the handshake on it before
//! returning a session, because `peer()` is synchronous and no unproven peer may be visible. One
//! inner stream then carries framed logical streams (`OPEN`, `DATA`, `FIN`, `RESET`), so a
//! single-stream inner gains many streams and a many-stream inner is not asked for more than one.
//! Stream ids are unique by side (initiator even, responder odd), frames are capped at 16 KiB,
//! per-stream and outbound queues are bounded, and the handshake of a connect or accept has a
//! deadline (a wait for an accept-side handshake slot is outside it). A
//! reader that stops reading propagates backpressure through the peer's writer instead of buffering
//! without end.
//!
//! Concurrency is bounded too: at most 16 accept-side handshakes run at once (further accepts wait
//! for a slot), and a session holds at most 64 streams open at once, with a slot released when the
//! last half of a stream drops. A fatal frame tears the session down: pending reads fail closed,
//! `wait_closed` wakes, and no new stream opens. The deadline covers the handshake only; a session
//! that completes the handshake and then idles has no idle timeout, so a peer that stalls after the
//! handshake holds the session and its two pump tasks until the app, the inner transport, or a
//! fatal frame closes it.
//!
//! Only wrapper-to-wrapper sessions interoperate. A bare inner peer fails the tag and never reaches
//! the Noise reader, with no fallback and no downgrade. A future protocol version is a new tag and
//! prologue; both sides change together.
//!
//! # What the tests prove, and what they cannot
//!
//! The suite exercises a byte-carrying inner and proves: byte parity and a clean drain over the
//! wrapper; the accept side attributes the handshake's proven identity even when the inner
//! announces a different one; a fabricated signer, a transplanted or spliced signature, a foreign
//! signer, and a replayed flight yield no session; the dialer pins the responder to the dialed
//! identity and writes no third flight when it fails; application bytes never appear on the inner
//! wire; a fatal frame wakes `wait_closed` and fails pending reads closed; and the bounds (tag,
//! handshake cap, message and stream caps, queue backpressure, handshake deadline) hold.
//!
//! It cannot prove secrecy, forward secrecy, nonce discipline, or that this implementation ran the
//! handshake when a malicious build did not. `Sealed` remains a declaration that one reviewed
//! implementation and protocol review back, not a proof. The suite states what it falsifies; it
//! cannot falsify a wrapper that lies consistently with its own wire.
//!
//! One library limit is recorded here: the wrapper zeroizes its own copy of each handshake static,
//! but `snow` 0.10 does not zeroize the private key held inside its handshake state, so that copy
//! is scrubbed only when the state is dropped.

use std::sync::Arc;

use bifrost_core::{Addr, Error, NodeId};
use bifrost_transport::{Announced, Sealed, SecurityProfile, Session, Transport};
use ed25519_dalek::SigningKey;
pub use error::NoiseError;
pub use session::{NoiseSession, StreamRead, StreamWrite};
use snow::params::NoiseParams;
use tokio::sync::Semaphore;
use tokio::time;
use zeroize::Zeroize;

mod error;
mod handshake;
mod session;

use handshake::initiate;
use session::Role;

/// In-progress accept-side handshakes one wrapper runs at once; further accepts wait for a slot.
pub(crate) const MAX_HANDSHAKES: usize = 16;

/// The security profiles a [`Noise`] wrapper accepts.
///
/// Implemented for [`Announced`] (the upgrade case) and [`Sealed`] (redundant but sound), and
/// deliberately not for [`bifrost_transport::InProcess`]: an in-process identity is not a key, so
/// there is no private key for the handshake to prove.
///
/// The in-process profile is refused at construction:
///
/// ```compile_fail
/// fn wrappable<P: bifrost_noise::Wrappable>() {}
/// wrappable::<bifrost_transport::InProcess>();
/// ```
pub trait Wrappable: SecurityProfile {}

impl Wrappable for Announced {}
impl Wrappable for Sealed {}

/// A transport that seals an inner transport's sessions with its own handshake.
///
/// Construction takes the inner transport and the same 32-byte ed25519 seed that binds it: the
/// wrapper signs with that identity, and one address carries one [`NodeId`]. `node_id` and
/// `local_addr` delegate to the inner transport, `close` delegates, and every session's `peer` is
/// the identity the wrapper's handshake proved.
///
/// The seed is held in an ed25519 [`SigningKey`] that zeroizes on drop. The X25519 static used in
/// the handshake is generated fresh per handshake and its private half is zeroized as soon as it is
/// copied into the handshake state; it is never persisted.
pub struct Noise<T> {
    inner: T,
    identity: SigningKey,
    node: NodeId,
    handshakes: Arc<Semaphore>,
}

impl<T: Transport> Noise<T>
where
    T::Security: Wrappable,
{
    /// Wrap an inner transport bound under the identity `seed` derives.
    ///
    /// Fails with [`NoiseError::IdentityMismatch`] when `inner.node_id()` is not
    /// [`NodeId::from_ed25519_secret`] of `seed`: one address carries one identity, and a wrapper
    /// whose identity differed from its inner could not be routed to.
    pub fn new(inner: T, seed: [u8; NodeId::KEY_LEN]) -> Result<Self, NoiseError> {
        wire::PATTERN
            .parse::<NoiseParams>()
            .map_err(|_| NoiseError::UnsupportedPattern)?;
        let node = NodeId::from_ed25519_secret(&seed);
        let inner_node = inner.node_id();
        if node != inner_node {
            return Err(NoiseError::IdentityMismatch {
                local: node,
                inner: inner_node,
            });
        }
        let mut seed = seed;
        let identity = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self {
            inner,
            identity,
            node,
            handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
        })
    }
}

impl<T: Transport> Transport for Noise<T>
where
    T::Security: Wrappable,
    // The session owns two pump tasks over the inner stream halves, so they must outlive the
    // session value. Every concrete backend's halves are `'static`; this states the requirement the
    // task spawn needs instead of leaking it into the shared `Session` trait.
    <T::Session as Session>::Write: 'static,
    <T::Session as Session>::Read: 'static,
{
    type Security = Sealed;
    type Session = NoiseSession<T::Session>;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error> {
        let dialed = addr.node;
        let attempt = async {
            let session = self.inner.connect(addr).await?;
            let (mut write, mut read) = session.open_bi().await?;
            let established =
                initiate(&mut write, &mut read, &self.identity, self.node, dialed).await?;
            Ok::<_, NoiseError>((session, write, read, established))
        };
        match time::timeout(wire::HANDSHAKE_TIMEOUT, attempt).await {
            Ok(Ok((session, write, read, established))) => Ok(NoiseSession::start(
                session,
                write,
                read,
                established,
                Role::Initiator,
            )),
            Ok(Err(err)) => Err(err.into_connect()),
            Err(_) => Err(NoiseError::HandshakeTimeout.into_connect()),
        }
    }

    async fn accept(&self) -> Result<Self::Session, Error> {
        let session = self.inner.accept().await?;
        // Bound the handshakes this listener runs at once. The permit lives only for the
        // handshake, never for the session, so a busy listener queues accepts instead of running
        // an unbounded number of handshake states.
        let permit = self
            .handshakes
            .acquire()
            .await
            .map_err(|_| NoiseError::Closed.into_accept())?;
        let attempt = async {
            let (mut write, mut read) = session.accept_bi().await?;
            let established =
                handshake::respond(&mut write, &mut read, &self.identity, self.node).await?;
            Ok::<_, NoiseError>((write, read, established))
        };
        let outcome = time::timeout(wire::HANDSHAKE_TIMEOUT, attempt).await;
        drop(permit);
        match outcome {
            Ok(Ok((write, read, established))) => Ok(NoiseSession::start(
                session,
                write,
                read,
                established,
                Role::Responder,
            )),
            Ok(Err(err)) => Err(err.into_accept()),
            Err(_) => Err(NoiseError::HandshakeTimeout.into_accept()),
        }
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

/// The frozen v0 spelling of the wrapper protocol.
///
/// A wire contract has one home: these constants are it. The prologue and tag carry the version;
/// the context strings separate the two signing roles; the payload is always
/// `NodeId(32) || signature(64)`. Any change to these bytes is a new protocol version, and both the
/// tag and the prologue move with it, so old and new peers fail closed instead of negotiating down.
pub mod wire {
    /// The Noise pattern: XX transmits both statics, so each can be fresh per handshake.
    pub const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

    /// Hashed into the handshake before any DH; names the protocol and the pattern.
    pub const PROLOGUE: &[u8] = b"bifrost-noise/0 Noise_XX_25519_ChaChaPoly_SHA256";

    /// The cleartext tag both sides write first. A mismatch fails closed, with no fallback.
    pub const TAG: &[u8] = b"bifrost-noise/0\n";

    /// The domain separator before the initiator's handshake hash and static.
    pub const CTX_INITIATOR: &[u8] = b"bifrost-noise/0 initiator";

    /// The domain separator before the responder's handshake hash and static.
    pub const CTX_RESPONDER: &[u8] = b"bifrost-noise/0 responder";

    /// Every handshake payload is exactly this long: `NodeId(32) || signature(64)`.
    pub const PAYLOAD_LEN: usize = 96;

    /// Frame kind for opening a logical stream.
    pub const FRAME_OPEN: u8 = 0;
    /// Frame kind for one chunk of stream bytes.
    pub const FRAME_DATA: u8 = 1;
    /// Frame kind for a clean stream end.
    pub const FRAME_FIN: u8 = 2;
    /// Frame kind for an abandoned stream.
    pub const FRAME_RESET: u8 = 3;

    /// The deadline covering one connect or accept attempt, handshake included.
    pub(crate) const HANDSHAKE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);

    /// The largest handshake message accepted. XX messages here stay under 256 bytes.
    pub(crate) const MAX_HANDSHAKE_MESSAGE: usize = 1024;
}

#[cfg(test)]
mod handshake_tests;
#[cfg(test)]
mod session_tests;
