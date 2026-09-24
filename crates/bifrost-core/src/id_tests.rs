use crate::{CryptoKind, KeyError, NodeId, NodeIdParseError, derive_ed25519_child_secret};

// The key vectors. nauthy's `key_tests.rs` holds the same bytes, in the same order, under the same
// clause names, so a clause that drifts in one crate fails that crate's CI against the other's vector.

/// The public key the seed `[7; 32]` binds: a real identity, sign bit 0.
const A: [u8; 32] = [
    0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,
    0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c,
];

/// `A` plus the order-8 torsion point `EIGHT_TORSION[1]`: canonical, not small-order, and a second
/// spelling of `A` whose signatures the holder of `A`'s secret can forge.
const A_PLUS_T: [u8; 32] = [
    0x1f, 0x4f, 0x58, 0x0e, 0x73, 0xac, 0x20, 0x8f, 0x06, 0x76, 0x01, 0x90, 0xe9, 0xed, 0xc6, 0xf5,
    0x91, 0x67, 0x75, 0xda, 0xbd, 0x9c, 0x1c, 0xdc, 0xa3, 0x93, 0x17, 0x5c, 0x2d, 0x6d, 0x10, 0x83,
];

/// The identity point, `y = 1`.
const IDENTITY_POINT: [u8; 32] = {
    let mut key = [0; 32];
    key[0] = 1;
    key
};

/// The point of order two, `y = p - 1`.
const ORDER_TWO: [u8; 32] = {
    let mut key = [0xff; 32];
    key[0] = 0xec;
    key[31] = 0x7f;
    key
};

/// `y = p + 1`: the identity point in its second, non-canonical spelling.
const NON_CANONICAL: [u8; 32] = {
    let mut key = [0xff; 32];
    key[0] = 0xee;
    key[31] = 0x7f;
    key
};

/// `-A`: `A` with its sign bit flipped, sign bit 1.
const MINUS_A: [u8; 32] = {
    let mut key = A;
    key[31] ^= 0x80;
    key
};

fn ed25519(key: [u8; 32]) -> Result<NodeId, KeyError> {
    NodeId::try_new(CryptoKind::Ed25519, key)
}

#[test]
fn the_identity_point_is_refused_as_small_order() {
    assert_eq!(ed25519(IDENTITY_POINT), Err(KeyError::SmallOrder));
}

#[test]
fn the_all_zero_key_is_refused_as_small_order() {
    assert_eq!(ed25519([0; 32]), Err(KeyError::SmallOrder));
}

#[test]
fn the_order_two_point_is_refused_as_small_order() {
    assert_eq!(ed25519(ORDER_TWO), Err(KeyError::SmallOrder));
}

#[test]
fn bytes_off_the_curve_are_refused() {
    assert_eq!(ed25519([2; 32]), Err(KeyError::NotOnCurve));
}

#[test]
fn a_non_canonical_spelling_is_refused() {
    assert_eq!(ed25519(NON_CANONICAL), Err(KeyError::NotCanonical));
}

#[test]
fn a_torsion_twin_of_a_real_identity_is_refused() {
    assert!(ed25519(A).is_ok(), "the untwisted key is a real identity");
    assert_eq!(ed25519(A_PLUS_T), Err(KeyError::HasTorsion));
}

#[test]
fn a_sign_twin_parses_and_is_a_different_identity() {
    let a = ed25519(A).expect("A is a real identity");
    let minus_a = ed25519(MINUS_A).expect("-A is a real identity");
    assert_ne!(minus_a, a, "exact bytes name an identity; -A is not A");
}

#[test]
fn every_key_a_secret_binds_parses() {
    let mut sign_bit_one = 0;
    for seq in 0u8..200 {
        let id = NodeId::from_ed25519_secret(&[seq; NodeId::KEY_LEN]);
        assert_eq!(ed25519(*id.key()), Ok(id), "seed [{seq}; 32]");
        sign_bit_one += usize::from(id.key()[31] >> 7);
    }
    assert!(
        sign_bit_one > 0,
        "the seeds must reach keys with sign bit 1"
    );
}

#[test]
fn a_node_id_round_trips_through_its_string() {
    let id = NodeId::from_ed25519_secret(&[7u8; NodeId::KEY_LEN]);
    let parsed: NodeId = id.to_string().parse().expect("valid identity string");
    assert_eq!(id, parsed);
}

#[test]
fn a_string_naming_a_torsion_twin_is_refused_at_parse() {
    let text = format!(
        "ed01{}",
        data_encoding::BASE32_NOPAD.encode(&A_PLUS_T).to_lowercase()
    );
    assert_eq!(
        text.parse::<NodeId>(),
        Err(NodeIdParseError::Key(KeyError::HasTorsion))
    );
}

#[test]
fn mem_counter_identities_are_all_valid_keys() {
    // The in-process transport binds under the key its counter seeds, the counter little-endian in the
    // first eight bytes. Read as a key, most of those counters name no identity (the first is the
    // identity point); read as a seed, every one does.
    for seq in 1u64..=10_000 {
        let mut seed = [0u8; NodeId::KEY_LEN];
        seed[..8].copy_from_slice(&seq.to_le_bytes());
        let id = NodeId::from_ed25519_secret(&seed);
        assert_eq!(ed25519(*id.key()), Ok(id), "counter {seq}");
    }
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
    // the machine adopts the secret and comes up as this id. This is the whole derived-identity mechanic.
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
    // Typed, so a return that stops wiping itself is a compile error here.
    let child: zeroize::Zeroizing<[u8; NodeId::KEY_LEN]> =
        derive_ed25519_child_secret(&root, "desk");
    // The child is never the root itself: the root stays on the owner's laptop; only a scoped child is
    // handed out as the derived-key payload a device adopts.
    assert_ne!(*child, root);
    // Domain-separated from any other KDF over the same root. A sibling derivation uses the same BLAKE3
    // primitive with a DIFFERENT context; a device seed and any sibling seed for one root must never
    // coincide, or adopting a device would leak the sibling seed (and vice versa). This pins the separation
    // so a refactor that collapses the contexts trips here.
    let sibling_seed = blake3::derive_key("bifrost sibling derivation v1", &root);
    assert_ne!(*child, sibling_seed);
}

#[test]
fn a_child_secret_uses_the_bifrost_context() {
    assert_eq!(
        *derive_ed25519_child_secret(&[9; 32], "desk"),
        blake3::derive_key("bifrost device identity v1: desk", &[9; 32])
    );
}

#[test]
fn display_carries_the_suite_tag() {
    let id = NodeId::from_ed25519_secret(&[0u8; NodeId::KEY_LEN]);
    assert!(id.to_string().starts_with("ed01"));
}

/// The key text format both libraries print: this literal is asserted byte for byte wherever an
/// Ed25519 key is printed in it, so either side drifting fails its own CI. It is key `A`, the one the
/// seed `[7; 32]` binds, and its body holds both an `s` and an `i` for the lookalike tests below.
const SHARED_VECTOR: &str = "ed015jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwa";

#[test]
fn the_key_text_is_the_shared_vector() {
    let id = ed25519(A).expect("A is a real identity");
    assert_eq!(id.to_string(), SHARED_VECTOR);
    assert_eq!(SHARED_VECTOR.parse::<NodeId>(), Ok(id));
}

#[test]
fn an_uppercase_key_text_parses() {
    let id = ed25519(A).expect("A is a real identity");
    assert_eq!(SHARED_VECTOR.to_ascii_uppercase().parse::<NodeId>(), Ok(id));
}

#[test]
fn rejects_unknown_suite() {
    let err = "zz99aaaaaaaa".parse::<NodeId>().unwrap_err();
    assert_eq!(err, NodeIdParseError::UnknownSuite);
}

#[test]
fn rejects_wrong_length() {
    let err = "ed01aa".parse::<NodeId>().unwrap_err();
    assert!(matches!(
        err,
        NodeIdParseError::WrongLength | NodeIdParseError::BadEncoding
    ));
}

/// `text` with the first `ascii` after the tag swapped for `lookalike`.
fn swap_first(text: &str, ascii: char, lookalike: char) -> String {
    let (tag, body) = text.split_at(4);
    format!("{tag}{}", body.replacen(ascii, &lookalike.to_string(), 1))
}

#[test]
fn a_long_s_in_place_of_s_is_refused() {
    // U+017F uppercases to ASCII `S` under Unicode rules, so a Unicode fold would read this as the key.
    let text = swap_first(SHARED_VECTOR, 's', '\u{17F}');
    assert_eq!(text.parse::<NodeId>(), Err(NodeIdParseError::BadEncoding));
}

#[test]
fn a_dotless_i_in_place_of_i_is_refused() {
    // U+0131 uppercases to ASCII `I` under Unicode rules.
    let text = swap_first(SHARED_VECTOR, 'i', '\u{131}');
    assert_eq!(text.parse::<NodeId>(), Err(NodeIdParseError::BadEncoding));
}
