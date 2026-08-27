use crate::{CryptoKind, NodeId, NodeIdParseError};

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
