use bifrost_core::NodeId;

use super::Secret;

#[test]
fn generated_secrets_are_distinct() {
    let (first, second) = (Secret::generate().unwrap(), Secret::generate().unwrap());
    assert_ne!(first.node_id(), second.node_id());
}

#[test]
fn taking_a_seed_wipes_the_callers_copy() {
    let mut seed = [7; 32];
    let secret = Secret::take(&mut seed);
    assert_eq!(seed, [0; 32]);
    secret.with_bytes(|held| assert_eq!(held, &[7; 32]));
}

#[test]
fn the_seed_lent_is_the_seed_held() {
    let secret = Secret::copy_of(&[3; 32]);
    secret.with_bytes(|held| assert_eq!(held, &[3; 32]));
    assert_eq!(secret.node_id(), NodeId::from_ed25519_secret(&[3; 32]));
}

#[test]
fn a_child_binds_the_node_id_its_derivation_predicts() {
    let root = Secret::copy_of(&[5; 32]);
    let child = root.derive_child("laptop");
    assert_eq!(child.node_id(), NodeId::derive_ed25519(&[5; 32], "laptop"));
    assert_ne!(
        root.derive_child("laptop").node_id(),
        root.derive_child("phone").node_id()
    );
}

#[test]
fn debug_names_the_node_and_never_the_seed() {
    let secret = Secret::copy_of(&[0xab; 32]);
    let shown = format!("{secret:?}");
    assert!(shown.contains(&secret.node_id().to_string()));
    assert!(!shown.to_lowercase().contains("abab"));
    assert!(!shown.contains("171"));
}
