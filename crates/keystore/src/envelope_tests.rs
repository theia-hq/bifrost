use bifrost_core::{CryptoKind, NodeId};
use zeroize::Zeroizing;

use super::{
    AT_KDF, AT_KIND, AT_LANES, AT_MEMORY, AT_METHOD, AT_NONCE, AT_PASSES, AT_PUBLIC, AT_SALT,
    AT_TAG, AT_VERSION, Cost, Envelope, HEADER_LEN, Parsed, Refusal, SEALED_LEN, SIGNATURE, parse,
};
use crate::error::FormatError;
use crate::method::Method;
use crate::passphrase::Passphrase;
use crate::secret::Secret;

/// A version 1 sealed key file, byte for byte. THE format test: a file this build wrote must open
/// to the same key forever, so these bytes are literal, never computed at test time.
///
/// They were produced outside this crate, from the layout in the module docs alone: Argon2id by the
/// OpenSSL 3.6 CLI (`openssl kdf ... ARGON2ID`, version 19), XChaCha20-Poly1305 by an implementation
/// written from RFC 8439 and the XChaCha draft and checked against both documents' published vectors,
/// and the public key by `openssl pkey`. So they pin that the layout doc is the whole format, and not
/// only that this code agrees with itself.
///
/// Inputs: seed `00 01 .. 1f`; passphrase `correct horse battery staple`; salt `a0 .. af`; nonce
/// `b0 .. c7`; Argon2id at 64 MiB, 3 passes, 1 lane.
#[rustfmt::skip]
const GOLDEN: [u8; SEALED_LEN] = [
    0x54, 0x48, 0x45, 0x49, 0x41, 0x4b, 0x45, 0x59, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
    0x35, 0x27, 0x00, 0x98, 0x56, 0x9e, 0x97, 0x3d, 0x74, 0x0e, 0xc9, 0xf6, 0x32, 0x65, 0x6d, 0xa9,
    0x09, 0xc5, 0xc6, 0x85, 0x0e, 0x0f, 0x0b, 0x86, 0xba, 0x61, 0xc3, 0xf6, 0x9c, 0x1a, 0x09, 0xf9,
    0x2c, 0x8d, 0x90, 0x78, 0x02, 0x2a, 0x68, 0x5a, 0xca, 0x9b, 0x6d, 0xfe, 0x9d, 0x3d, 0x6e, 0x7c,
];

/// The sealed half of a second version 1 file: the header of [`GOLDEN`] exactly, sealed instead under
/// the passphrase `café crème` in its NFC byte form, `63 61 66 c3 a9 20 63 72 c3 a8 6d 65`. Produced
/// the same way as [`GOLDEN`], with the byte form taken from Python's `unicodedata`, not from the
/// normalizer this crate uses. It pins the passphrase's byte form as part of the format.
#[rustfmt::skip]
const GOLDEN_NFC_SEALED: [u8; SEALED_LEN - HEADER_LEN] = [
    0xe8, 0x4d, 0xe7, 0xa3, 0xe7, 0xcc, 0x58, 0xac, 0x76, 0x38, 0x6f, 0xda, 0xba, 0x78, 0x19, 0x4e,
    0x26, 0xf9, 0xea, 0x5a, 0x06, 0xf2, 0xfa, 0x5d, 0xa4, 0xab, 0x49, 0x0e, 0x67, 0xf1, 0x87, 0x42,
    0x5c, 0x1e, 0x4f, 0x69, 0x10, 0x56, 0x6e, 0x89, 0x77, 0x73, 0xf1, 0xec, 0xb2, 0x09, 0x53, 0x75,
];

/// The golden seed's ed25519 public key, as `openssl pkey` derived it.
#[rustfmt::skip]
const GOLDEN_PUBLIC: [u8; 32] = [
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
];

fn golden_seed() -> [u8; 32] {
    core::array::from_fn(|at| at as u8)
}

fn golden_salt() -> [u8; 16] {
    core::array::from_fn(|at| 0xa0 + at as u8)
}

fn golden_nonce() -> [u8; 24] {
    core::array::from_fn(|at| 0xb0 + at as u8)
}

fn passphrase(text: &str) -> Passphrase {
    Passphrase::new(Zeroizing::new(text.as_bytes().to_vec())).unwrap()
}

fn sealed(bytes: &[u8]) -> Envelope {
    match parse(bytes) {
        Ok(Parsed::Sealed(envelope)) => envelope,
        Ok(Parsed::Plain(_)) => panic!("parsed as a plain seed"),
        Err(error) => panic!("did not parse: {error}"),
    }
}

fn refusal(bytes: &[u8]) -> FormatError {
    match parse(bytes) {
        Err(error) => error,
        Ok(Parsed::Plain(_)) => panic!("{} bytes were read as a plain seed", bytes.len()),
        Ok(Parsed::Sealed(_)) => panic!("{} bytes were accepted as a sealed file", bytes.len()),
    }
}

/// A sealed file at the cheapest cost a file may carry, for the tests that unlock many times.
fn floor_image(secret: &Secret, public: NodeId, under: &Passphrase) -> [u8; SEALED_LEN] {
    *Envelope::seal_with(
        secret,
        public,
        under,
        Cost::FLOOR,
        &golden_salt(),
        &golden_nonce(),
    )
    .unwrap()
    .image()
}

#[test]
fn the_golden_vector_opens_to_its_seed() {
    let envelope = sealed(&GOLDEN);
    assert_eq!(envelope.method(), Method::Passphrase);
    assert_eq!(
        envelope.node_id(),
        NodeId::new(CryptoKind::Ed25519, GOLDEN_PUBLIC)
    );
    let secret = envelope
        .open(&passphrase("correct horse battery staple"))
        .unwrap();
    secret.with_bytes(|seed| assert_eq!(seed, &golden_seed()));
    assert_eq!(secret.node_id(), envelope.node_id());
}

#[test]
fn a_decomposed_typing_of_the_passphrase_opens_the_nfc_golden_vector() {
    let image: [u8; SEALED_LEN] = [&GOLDEN[..HEADER_LEN], &GOLDEN_NFC_SEALED[..]]
        .concat()
        .try_into()
        .unwrap();
    // `e` then a combining accent: the spelling a dead-key terminal may send, not the one sealed.
    let typed =
        Passphrase::try_from(Zeroizing::new("cafe\u{301} cre\u{300}me".to_owned())).unwrap();
    let secret = sealed(&image).open(&typed).unwrap();
    secret.with_bytes(|seed| assert_eq!(seed, &golden_seed()));
}

#[test]
fn this_build_writes_the_golden_vector_byte_for_byte() {
    let secret = Secret::copy_of(&golden_seed());
    let envelope = Envelope::seal_with(
        &secret,
        secret.node_id(),
        &passphrase("correct horse battery staple"),
        Cost::parse(64 * 1024, 3, 1).unwrap(),
        &golden_salt(),
        &golden_nonce(),
    )
    .unwrap();
    assert_eq!(envelope.image(), &GOLDEN);
}

#[test]
fn every_seal_uses_the_golden_cost_and_draws_a_fresh_salt_and_nonce() {
    let secret = Secret::copy_of(&golden_seed());
    let under = passphrase("correct horse battery staple");
    let first = Envelope::seal(&secret, &under).unwrap();
    let second = Envelope::seal(&secret, &under).unwrap();
    for envelope in [&first, &second] {
        assert_eq!(
            envelope.image()[AT_MEMORY..AT_SALT],
            GOLDEN[AT_MEMORY..AT_SALT]
        );
    }
    assert_ne!(
        first.image()[AT_SALT..AT_NONCE],
        second.image()[AT_SALT..AT_NONCE]
    );
    assert_ne!(
        first.image()[AT_NONCE..AT_PUBLIC],
        second.image()[AT_NONCE..AT_PUBLIC]
    );
    assert!(first.open(&under).is_ok() && second.open(&under).is_ok());
}

#[test]
fn a_wrong_passphrase_and_a_damaged_file_are_one_refusal() {
    let secret = Secret::copy_of(&golden_seed());
    let under = passphrase("correct horse battery staple");
    let image = floor_image(&secret, secret.node_id(), &under);

    assert!(matches!(
        sealed(&image).open(&passphrase("Correct horse battery staple")),
        Err(Refusal::Unlock)
    ));
    // One flipped bit in every authenticated field. The Argon2id fields flip to values still inside
    // the bounds, so the damage reaches the cipher rather than the parser. The public key is the field
    // only the associated data protects: nothing else ties the header to the ciphertext.
    for (field, at, bit) in [
        ("memory", AT_MEMORY + 3, 0x01),
        ("passes", AT_PASSES + 3, 0x01),
        ("lanes", AT_LANES + 3, 0x02),
        ("salt", AT_SALT, 0x01),
        ("nonce", AT_NONCE + 23, 0x80),
        ("public key", AT_PUBLIC + 7, 0x10),
        ("ciphertext", HEADER_LEN + 31, 0x01),
        ("tag", AT_TAG, 0x40),
    ] {
        let mut damaged = image;
        damaged[at] ^= bit;
        assert!(
            matches!(sealed(&damaged).open(&under), Err(Refusal::Unlock)),
            "a damaged {field} was not refused as a failed unlock"
        );
    }
}

#[test]
fn a_header_naming_another_node_is_refused_even_with_the_right_passphrase() {
    let secret = Secret::copy_of(&golden_seed());
    let other = Secret::copy_of(&[7; 32]);
    let under = passphrase("correct horse battery staple");
    let image = floor_image(&secret, other.node_id(), &under);
    let envelope = sealed(&image);
    assert_eq!(envelope.node_id(), other.node_id());
    assert!(matches!(envelope.open(&under), Err(Refusal::Inconsistent)));
}

#[test]
fn a_plain_file_is_exactly_32_bytes() {
    assert!(matches!(parse(&[9; 32]), Ok(Parsed::Plain(seed)) if seed == &[9; 32]));
    for found in [0, 1, 31, 33, 143, 144, 145] {
        assert_eq!(
            refusal(&vec![9; found]),
            FormatError::Size {
                found: found as u64
            }
        );
    }
}

#[test]
fn a_cut_down_sealed_file_is_never_read_as_a_plain_seed() {
    // Cut to exactly 32 bytes it has the plain length; the signature decides first.
    for found in [8, 9, 32, 143] {
        assert_eq!(
            refusal(&GOLDEN[..found]),
            FormatError::SealedSize {
                found: found as u64
            }
        );
    }
    let mut padded = GOLDEN.to_vec();
    padded.push(0);
    assert_eq!(refusal(&padded), FormatError::SealedSize { found: 145 });
}

#[test]
fn an_unknown_version_is_named_before_its_length_is_judged() {
    assert_eq!(
        refusal(&[&SIGNATURE[..], &[2]].concat()),
        FormatError::Version { found: 2 }
    );
    for found in [0, 2, 255] {
        let mut image = GOLDEN;
        image[AT_VERSION] = found;
        assert_eq!(refusal(&image), FormatError::Version { found });
    }
}

#[test]
fn only_registered_kinds_methods_and_derivations_parse() {
    // Method 1 is the passphrase. No other value is registered, so a method reserved for the future
    // cannot be carried by a file this build accepts.
    for found in [0, 2, 3, 255] {
        let mut image = GOLDEN;
        image[AT_KIND] = found;
        assert_eq!(refusal(&image), FormatError::Kind { found });

        let mut image = GOLDEN;
        image[AT_METHOD] = found;
        assert_eq!(refusal(&image), FormatError::Method { found });

        let mut image = GOLDEN;
        image[AT_KDF] = found;
        assert_eq!(refusal(&image), FormatError::Kdf { found });
    }
}

fn with_cost(memory_kib: u32, passes: u32, lanes: u32) -> [u8; SEALED_LEN] {
    let mut image = GOLDEN;
    image[AT_MEMORY..AT_PASSES].copy_from_slice(&memory_kib.to_be_bytes());
    image[AT_PASSES..AT_LANES].copy_from_slice(&passes.to_be_bytes());
    image[AT_LANES..AT_SALT].copy_from_slice(&lanes.to_be_bytes());
    image
}

#[test]
fn a_cost_outside_the_bounds_is_refused_before_any_key_is_derived() {
    // Refused by the parser, so no `Envelope` exists to derive from: a hostile file costs a read.
    for (memory_kib, passes, lanes) in [
        (u32::MAX, 3, 1),
        (256 * 1024 + 1, 3, 1),
        (19 * 1024 - 1, 3, 1),
        (64 * 1024, u32::MAX, 1),
        (64 * 1024, 11, 1),
        (64 * 1024, 1, 1),
        (64 * 1024, 3, 0),
        (64 * 1024, 3, 9),
    ] {
        assert_eq!(
            refusal(&with_cost(memory_kib, passes, lanes)),
            FormatError::Cost {
                memory_kib,
                passes,
                lanes
            }
        );
    }
}

#[test]
fn the_bounds_are_inclusive_and_hold_both_costs_this_crate_uses() {
    for (memory_kib, passes, lanes) in [(256 * 1024, 10, 8), (19 * 1024, 2, 1)] {
        assert!(matches!(
            parse(&with_cost(memory_kib, passes, lanes)),
            Ok(Parsed::Sealed(_))
        ));
    }
    assert_eq!(Cost::parse(19 * 1024, 2, 1), Ok(Cost::FLOOR));
    assert_eq!(Cost::parse(64 * 1024, 3, 1), Ok(Cost::DEFAULT));
}
