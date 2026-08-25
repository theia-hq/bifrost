use crate::{CryptoKind, NodeId, NodeIdParseError};

#[test]
fn roundtrips_through_string() {
    let id = NodeId::new(CryptoKind::Ed25519, [7u8; NodeId::KEY_LEN]);
    let parsed: NodeId = id.to_string().parse().expect("valid identity string");
    assert_eq!(id, parsed);
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
