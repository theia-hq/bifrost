use crate::{CryptoKind, NodeId, NodeIdParseError, derive_ed25519_child_secret};

#[test]
fn roundtrips_through_string() {
    let id = NodeId::new(CryptoKind::Ed25519, [7u8; NodeId::KEY_LEN]);
    let parsed: NodeId = id.to_string().parse().expect("valid identity string");
    assert_eq!(id, parsed);
}

#[test]
fn derives_the_ed25519_public_key_from_a_secret() {
    let secret = [7u8; NodeId::KEY_LEN];
    let id = NodeId::from_ed25519_secret(&secret);
    let expected = ed25519_dalek::SigningKey::from_bytes(&secret)
        .verifying_key()
        .to_bytes();
    assert_eq!(id.kind(), CryptoKind::Ed25519);
    assert_eq!(id.key(), &expected);
    // Deterministic: the same secret always yields the same identity.
    assert_eq!(id, NodeId::from_ed25519_secret(&secret));
}

#[test]
fn derives_a_device_identity_from_a_root_and_label() {
    let root = [3u8; NodeId::KEY_LEN];
    let device = NodeId::derive_ed25519(&root, "ci-runner");
    // The derived id is exactly the identity of the derived child secret: the owner computes it offline,
    // the machine adopts the secret and comes up as this id. This is the whole `--authkey` mechanic.
    let child = derive_ed25519_child_secret(&root, "ci-runner");
    assert_eq!(device, NodeId::from_ed25519_secret(&child));
    assert_eq!(device.kind(), CryptoKind::Ed25519);
    // Deterministic: same root + label always the same id (instant addressing, no registry).
    assert_eq!(device, NodeId::derive_ed25519(&root, "ci-runner"));
}

#[test]
fn distinct_labels_and_roots_derive_distinct_devices() {
    let root = [3u8; NodeId::KEY_LEN];
    let other = [4u8; NodeId::KEY_LEN];
    let desk = NodeId::derive_ed25519(&root, "desk");
    let runner = NodeId::derive_ed25519(&root, "ci-runner");
    let alien = NodeId::derive_ed25519(&other, "desk");
    assert_ne!(
        desk, runner,
        "different labels under one root are different devices"
    );
    assert_ne!(
        desk, alien,
        "the same label under a different root is a different device"
    );
}

#[test]
fn a_child_secret_is_domain_separated_from_the_root_and_other_derivations() {
    let root = [9u8; NodeId::KEY_LEN];
    let child = derive_ed25519_child_secret(&root, "desk");
    // The child is never the root itself: the root stays on the owner's laptop; only a scoped child is
    // handed out as an authkey.
    assert_ne!(child, root);
    // Domain-separated from any other KDF over the same root. The ssh host seed uses the same BLAKE3
    // primitive with a different context; a device seed and a host seed for one root must never coincide,
    // or adopting a device would leak its host key (and vice versa). This pins the separation so a
    // refactor that collapses the contexts trips here.
    let host_seed = blake3::derive_key("theia sshh host key v1", &root);
    assert_ne!(child, host_seed);
}

#[test]
fn display_carries_the_suite_tag() {
    let id = NodeId::new(CryptoKind::Ed25519, [0u8; NodeId::KEY_LEN]);
    assert!(id.to_string().starts_with("bf01"));
}

#[test]
fn rejects_unknown_suite() {
    let err = "zz99aaaaaaaa".parse::<NodeId>().unwrap_err();
    assert_eq!(err, NodeIdParseError::UnknownSuite);
}

#[test]
fn rejects_wrong_length() {
    let err = "bf01aa".parse::<NodeId>().unwrap_err();
    assert!(matches!(
        err,
        NodeIdParseError::WrongLength | NodeIdParseError::BadEncoding
    ));
}
