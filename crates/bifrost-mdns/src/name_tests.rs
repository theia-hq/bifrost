//! The blinded name: its shape, that it changes, and that only a holder of the key recognises it.

use bifrost_core::{CryptoKind, NodeId};

use super::name::{self, NAME_LEN, Resolver};

/// A name is one label of base32 with no `0` or `1`, so it never parses as a key.
#[test]
fn a_name_parses_as_no_node_id() {
    let name = fresh(&node(1));
    assert!(
        name.parse::<NodeId>().is_err(),
        "{name} must not parse as a key"
    );
    assert_eq!(name.len(), NAME_LEN);
    assert_eq!(name.len(), 39);
}

/// Two names for one key share nothing an observer could link them by.
#[test]
fn two_names_for_one_key_differ() {
    let n = node(2);
    let (first, second) = (fresh(&n), fresh(&n));
    let runs = |name: &str| -> Vec<String> {
        name.as_bytes()
            .windows(8)
            .map(|run| String::from_utf8_lossy(run).into_owned())
            .collect()
    };
    let second_runs = runs(&second);
    let shared: Vec<String> = runs(&first)
        .into_iter()
        .filter(|run| second_runs.contains(run))
        .collect();
    assert!(
        shared.is_empty(),
        "{first} and {second} share the runs {shared:?}"
    );
}

/// The holder of a key recognises that key's names, and only that key's.
#[test]
fn a_holder_of_the_key_recognises_the_name() {
    let (n, m) = (node(3), node(4));
    assert!(Resolver::of(&n).matches(&fresh(&n)));
    assert!(!Resolver::of(&m).matches(&fresh(&n)));
}

/// A name has one spelling: the lowercase one it is sent in. Anything else is refused.
#[test]
fn only_a_name_decodes() {
    let n = node(5);
    let name = fresh(&n);
    assert!(Resolver::of(&n).matches(&name));
    let mixed: String = name
        .chars()
        .enumerate()
        .map(|(at, c)| {
            if at % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    for other in [name.to_ascii_uppercase(), mixed] {
        assert!(!name::decodes(&other), "{other} is not a name");
        assert!(!Resolver::of(&n).matches(&other), "{other} is not n's name");
    }
    assert!(!name::decodes(&n.to_string()), "a key is not a name");
    assert!(!name::decodes(&name[1..]), "a short name is not a name");
    assert!(
        !name::decodes(&format!("0{}", &name[1..])),
        "a name outside the alphabet is not a name"
    );
}

fn fresh(node: &NodeId) -> String {
    name::fresh(node).expect("the system has randomness")
}

fn node(seed: u8) -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [seed; NodeId::KEY_LEN])
}
