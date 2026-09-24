use bifrost_core::{CryptoKind, NodeId};
use bifrost_transport::Transport as _;

use crate::{MemTransport, seed_for};

#[test]
fn a_counter_seed_binds_the_identity_it_derives() {
    let bound = MemTransport::bind_with_secret(seed_for(u64::MAX));
    assert_eq!(
        bound.node_id(),
        NodeId::from_ed25519_secret(&seed_for(u64::MAX))
    );
}

#[test]
fn every_bind_is_a_distinct_identity_that_parses() {
    let (first, second) = (MemTransport::bind(), MemTransport::bind());
    assert_ne!(first.node_id(), second.node_id());
    for node in [first.node_id(), second.node_id()] {
        assert_eq!(NodeId::try_new(CryptoKind::Ed25519, *node.key()), Ok(node));
    }
}
