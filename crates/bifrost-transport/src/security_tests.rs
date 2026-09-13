use crate::security::{
    Announced, ChannelProtection, Confidential, InProcess, PeerProof, PeerProven, Sealed, Secure,
    Security, SecurityProfile,
};

#[test]
fn markers_declare_their_properties() {
    assert_eq!(
        <Sealed as SecurityProfile>::SECURITY,
        Security {
            peer: PeerProof::Proven,
            channel: ChannelProtection::Aead,
        }
    );
    assert_eq!(
        <Announced as SecurityProfile>::SECURITY,
        Security {
            peer: PeerProof::Announced,
            channel: ChannelProtection::Plain,
        }
    );
    assert_eq!(
        <InProcess as SecurityProfile>::SECURITY,
        Security {
            peer: PeerProof::InProcess,
            channel: ChannelProtection::InProcess,
        }
    );
}

/// The capability set and the declared [`Security`] value agree per marker: the marker that carries
/// a capability reads back as that capability through the one runtime predicate, and the marker that
/// does not cannot. Both halves are emitted from one `profiles!` row, so a one-sided edit cannot
/// compile; this test pins the row itself. `Announced` has no positive call here: the `compile_fail`
/// doctest on the marker pins its rejection.
#[test]
fn capabilities_match_the_declared_security() {
    fn peer_proven<P: PeerProven>() {}
    fn confidential<P: Confidential>() {}
    fn secure<P: Secure>() {}

    peer_proven::<Sealed>();
    confidential::<Sealed>();
    secure::<Sealed>();
    assert!(<Sealed as SecurityProfile>::SECURITY.proves_peer());

    peer_proven::<InProcess>();
    confidential::<InProcess>();
    secure::<InProcess>();
    assert!(<InProcess as SecurityProfile>::SECURITY.proves_peer());

    assert!(!<Announced as SecurityProfile>::SECURITY.proves_peer());
}
