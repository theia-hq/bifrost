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
//! honest. What backs [`Sealed`] is the handshake binding the peer to its `NodeId` plus the channel
//! guarantees of the backing implementation (for iroh, QUIC with TLS 1.3 and raw public keys). The
//! conformance suite falsifies a mis-attributing fabricator and refuses a dial to a key the receiver
//! does not hold; it cannot catch a transport that echoes the dialed key back without proving it,
//! and it inspects no bytes. Declaration honesty, forward secrecy, nonce discipline, replay
//! resistance against an active attacker, and post-compromise posture are protocol review of the
//! handshake and its library, not properties a black-box test can establish. Admitting a new
//! transport is the checklist in the crate docs.
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

impl Security {
    /// Whether this declaration says the peer's identity is proven.
    ///
    /// The one runtime predicate for a consumer whose transport is chosen dynamically; a consumer
    /// whose transport is static requires [`PeerProven`] as a bound instead. [`PeerProof::Proven`]
    /// is a completed handshake, [`PeerProof::InProcess`] is exact by construction, and
    /// [`PeerProof::Announced`] is a claim the peer made about itself.
    #[must_use]
    pub const fn proves_peer(self) -> bool {
        matches!(self.peer, PeerProof::Proven | PeerProof::InProcess)
    }
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

/// The sealed profile set, declared as one table so a marker's [`Security`] value and its capability
/// impls are emitted from the same row and cannot drift apart.
///
/// Each row is the marker (with its docs), the properties it declares, and the capability traits a
/// bounded consumer may rely on. [`Secure`] follows from the two capabilities rather than a row of
/// its own, so a profile cannot claim it without both. Adding a profile is adding a row here; the
/// seal and the compiler-facing bounds follow from it.
macro_rules! profiles {
    (
        $(
            $(#[$doc:meta])*
            $marker:ident => $security:expr $(, proves [ $($cap:ident),* $(,)? ] )? ;
        )+
    ) => {
        $(
            $(#[$doc])*
            pub enum $marker {}

            impl sealed::Sealed for $marker {}

            impl SecurityProfile for $marker {
                const SECURITY: Security = $security;
            }

            $(
                $(impl $cap for $marker {})*
            )?
        )+
    };
}

profiles! {
    /// A handshake proves the peer holds the `NodeId` key and the channel is end-to-end AEAD.
    ///
    /// It is a declaration: the compiler cannot verify the handshake. Conformance falsifies a
    /// mis-attributing fabricator and a dial to a key the receiver does not hold; it cannot catch a
    /// transport that echoes the dialed key back or sends plaintext under this marker. Declaration
    /// honesty, forward secrecy, nonce discipline, and replay resistance are protocol review.
    Sealed => Security { peer: PeerProof::Proven, channel: ChannelProtection::Aead },
        proves [PeerProven, Confidential];

    /// The peer key is self-announced over a plaintext channel. Public traffic only.
    ///
    /// It carries neither capability, so a bounded consumer rejects it at compile time:
    ///
    /// ```compile_fail,E0277
    /// fn needs_proven<P: bifrost_transport::PeerProven>() {}
    /// needs_proven::<bifrost_transport::Announced>();
    /// ```
    Announced => Security { peer: PeerProof::Announced, channel: ChannelProtection::Plain },
        proves [];

    /// No wire: the identity is exact by construction and the bytes stay inside one process.
    ///
    /// This is a trust-unit declaration the compiler cannot check. It is for test scaffolding and
    /// same-process composition, where the process boundary is the trust boundary, not for anything
    /// crossing a process or a network.
    InProcess => Security { peer: PeerProof::InProcess, channel: ChannelProtection::InProcess },
        proves [PeerProven, Confidential];
}

impl<T: PeerProven + Confidential> Secure for T {}

/// Closes [`SecurityProfile`] to the markers above: the trait is public, the seal is not.
mod sealed {
    pub trait Sealed {}
}
