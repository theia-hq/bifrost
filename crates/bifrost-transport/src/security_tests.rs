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

/// The capability traits compile for exactly the markers named in the contract. `Announced` has no
/// call here: the `compile_fail` doctest on the marker pins its rejection.
#[test]
fn capabilities_match_the_markers() {
    fn peer_proven<P: PeerProven>() {}
    fn confidential<P: Confidential>() {}
    fn secure<P: Secure>() {}

    peer_proven::<Sealed>();
    confidential::<Sealed>();
    secure::<Sealed>();
    peer_proven::<InProcess>();
    confidential::<InProcess>();
    secure::<InProcess>();
}
