//! What a transport proves about its peer and what it protects on the wire.
//!
//! Every [`Transport`](crate::Transport) names exactly one [`SecurityProfile`]: [`Sealed`],
//! [`Announced`], or [`InProcess`]. The profile is a type, so a consumer can require the properties
//! it needs as a bound ([`PeerProven`], [`Confidential`], [`Secure`]), and it carries a value
//! ([`SecurityProfile::SECURITY`]) for the seams that only see a session. The marker set is sealed: a
//! downstream crate cannot add a fourth, more permissive profile.
//!
//! The profile is a claim, not a proof. The type system forces every transport to state what it
//! provides and stops a bounded consumer from accepting less; it cannot make an implementation
//! honest. What backs [`Sealed`] is the handshake binding the peer to its `NodeId` (the conformance
//! suite falsifies a fabricator: a dial to a key the receiver does not hold yields no session) plus
//! the channel guarantees of the backing implementation (for iroh, QUIC with TLS 1.3 and raw public
//! keys). Forward secrecy, nonce discipline, replay resistance against an active attacker, and
//! post-compromise posture are protocol review of the handshake and its library, not properties a
//! black-box test can establish.
//!
//! | marker | peer identity | channel | carries |
//! | --- | --- | --- | --- |
//! | [`Sealed`] | proven by the handshake | end-to-end AEAD | traffic that trusts the peer or must stay private |
//! | [`Announced`] | self-announced, unproven | plaintext | public traffic only |
//! | [`InProcess`] | exact by construction, trusted by declaration | no wire | anything inside one process |

/// A transport security profile: what a transport proves about peers and protects on the wire.
///
/// Implemented only by the markers in this module ([`Sealed`], [`Announced`], [`InProcess`]), so the
/// set of profiles is closed. The marker type is the source of truth for compile-time bounds; the
/// associated value is the same declaration, readable where only the profile type is in scope.
pub trait SecurityProfile: sealed::Sealed {
    /// The declared properties, for the runtime seams that cannot see a concrete transport.
    const SECURITY: Security;
}

/// A profile that proves the peer holds the private key for its `NodeId`.
///
/// [`InProcess`] satisfies this by declaration: no third party is on the wire, because there is no
/// wire. [`Announced`] does not, and a consumer that requires this bound rejects it at compile time.
pub trait PeerProven: SecurityProfile {}

/// A profile whose channel hides its bytes from parties on the wire.
///
/// [`InProcess`] satisfies this by declaration: the bytes never leave the process. [`Announced`]
/// does not, and a consumer that requires this bound rejects it at compile time.
pub trait Confidential: SecurityProfile {}

/// Both capabilities at once: the peer is proven and the channel is confidential.
///
/// The bound for a consumer that hands a session something it trusts the peer with.
pub trait Secure: PeerProven + Confidential {}

/// The declared security of a transport: a peer-identity claim and a channel-protection claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Security {
    /// How the peer's identity is established.
    pub peer: PeerProof,
    /// What protects the bytes between the peers.
    pub channel: ChannelProtection,
}

/// How a transport establishes the peer's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerProof {
    /// A handshake proves the peer holds the private key for the `NodeId` it is reached under.
    Proven,
    /// The identity is exact by construction: no untrusted party is between the peers.
    InProcess,
    /// The peer states its own key; nothing proves it.
    Announced,
}

/// What protects the bytes between the peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelProtection {
    /// End-to-end authenticated encryption (AEAD).
    Aead,
    /// No wire: the bytes stay inside one process.
    InProcess,
    /// No channel protection.
    Plain,
}

/// A handshake proves the peer key and the channel is end-to-end AEAD.
///
/// It is a declaration: the compiler cannot verify the handshake, so a lying implementation is caught
/// by conformance (identity binding) and protocol review, not by the type.
pub enum Sealed {}

/// The peer key is self-announced over a plaintext channel. Public traffic only.
///
/// It carries neither capability, so a bounded consumer rejects it at compile time:
///
/// ```compile_fail
/// fn needs_proven<P: bifrost_transport::PeerProven>() {}
/// needs_proven::<bifrost_transport::Announced>();
/// ```
pub enum Announced {}

/// No wire: the identity is exact by construction and the bytes stay inside one process.
///
/// This is a trust-unit declaration the compiler cannot check. It is for test scaffolding and
/// same-process composition, where the process boundary is the trust boundary, not for anything
/// crossing a process or a network.
pub enum InProcess {}

impl sealed::Sealed for Sealed {}
impl sealed::Sealed for Announced {}
impl sealed::Sealed for InProcess {}

impl SecurityProfile for Sealed {
    const SECURITY: Security = Security {
        peer: PeerProof::Proven,
        channel: ChannelProtection::Aead,
    };
}

impl SecurityProfile for Announced {
    const SECURITY: Security = Security {
        peer: PeerProof::Announced,
        channel: ChannelProtection::Plain,
    };
}

impl SecurityProfile for InProcess {
    const SECURITY: Security = Security {
        peer: PeerProof::InProcess,
        channel: ChannelProtection::InProcess,
    };
}

impl PeerProven for Sealed {}
impl PeerProven for InProcess {}
impl Confidential for Sealed {}
impl Confidential for InProcess {}
impl<T: PeerProven + Confidential> Secure for T {}

/// Closes [`SecurityProfile`] to the markers above: the trait is public, the seal is not.
mod sealed {
    pub trait Sealed {}
}
