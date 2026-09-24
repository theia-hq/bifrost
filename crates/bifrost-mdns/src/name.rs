//! The name a serving node announces under: blinded, so only a holder of its key can tell it is
//! this node.
//!
//! A name is `base32(nonce ‖ tag)` in lowercase, where the nonce is 8 fresh random bytes and the
//! tag is the first 16 bytes of a BLAKE3 keyed hash of the nonce under a key derived from the
//! node's key text. Anyone who holds the node's key can recompute the tag and recognise the name;
//! anyone else sees 24 random-looking bytes that change with every nonce. This is the shape of
//! Bluetooth's resolvable private address, with the public key standing in for the resolving key.
//!
//! The name is one DNS label of [`NAME_LEN`] characters, so the host label the dependency derives
//! from it (`<name>-<port>`) still fits under 63. Its alphabet (`a-z`, `2-7`) has no `0` or `1`, so
//! a name never parses as a key.

use bifrost_core::NodeId;
use data_encoding::BASE32_NOPAD;

/// The BLAKE3 derivation context for a node's resolving key.
const CONTEXT: &str = "bifrost mdns instance v1";

/// Random bytes at the front of every name.
const NONCE_LEN: usize = 8;

/// Bytes of the keyed hash kept after the nonce.
const TAG_LEN: usize = 16;

/// The length of a name in characters: 24 bytes of base32 with no padding.
pub(crate) const NAME_LEN: usize = 39;

/// A fresh name for `node`, under a nonce drawn now.
///
/// An entropy failure is returned rather than papered over: a name from a weak or fixed nonce
/// would link this node's announcements, and the key itself is never a fallback.
pub(crate) fn fresh(node: &NodeId) -> Result<String, getrandom::Error> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce)?;
    let mut raw = [0; NONCE_LEN + TAG_LEN];
    raw[..NONCE_LEN].copy_from_slice(&nonce);
    raw[NONCE_LEN..].copy_from_slice(&Resolver::of(node).tag(&nonce));
    Ok(BASE32_NOPAD.encode(&raw).to_lowercase())
}

/// Whether `name` has the shape of a name at all: the right length and lowercase base32 throughout.
///
/// Checked before any hash, so a record that cannot be a name costs a length check and a decode.
pub(crate) fn decodes(name: &str) -> bool {
    decode(name).is_some()
}

/// The nonce and tag inside `name`, or `None` when it is not a name.
///
/// A name has one spelling, the lowercase one it is sent in. Any other would be a second table
/// entry for the same name, which a replay in mixed case could mint without end.
fn decode(name: &str) -> Option<[u8; NONCE_LEN + TAG_LEN]> {
    if name.len() != NAME_LEN || !name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return None;
    }
    let raw = BASE32_NOPAD
        .decode(name.to_ascii_uppercase().as_bytes())
        .ok()?;
    raw.try_into().ok()
}

/// What recognises one node's names: the key derived from its key text.
///
/// The key's text is the input, suite tag included, so a later suite gets names of its own with no
/// further rule.
pub(crate) struct Resolver([u8; 32]);

impl Resolver {
    /// The resolver for `node`'s names.
    pub(crate) fn of(node: &NodeId) -> Self {
        Self(blake3::derive_key(CONTEXT, node.to_string().as_bytes()))
    }

    /// Whether `name` is one of this node's names.
    ///
    /// A name that does not decode is refused before any hash. The tag is compared with plain `==`:
    /// it guards nothing secret (anyone holding the public key can mint it), so a timing difference
    /// tells an observer nothing.
    pub(crate) fn matches(&self, name: &str) -> bool {
        #[cfg(test)]
        counter::count_match();
        let Some(raw) = decode(name) else {
            return false;
        };
        let (nonce, tag) = raw.split_at(NONCE_LEN);
        self.tag(nonce) == tag
    }

    fn tag(&self, nonce: &[u8]) -> [u8; TAG_LEN] {
        let mut tag = [0; TAG_LEN];
        tag.copy_from_slice(&blake3::keyed_hash(&self.0, nonce).as_bytes()[..TAG_LEN]);
        tag
    }
}

#[cfg(test)]
pub(crate) mod counter {
    use core::cell::Cell;

    std::thread_local! {
        static MATCHES: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count_match() {
        MATCHES.with(|count| count.set(count.get() + 1));
    }

    /// How many names this thread has tested against a key so far.
    pub(crate) fn matches_run() -> usize {
        MATCHES.with(Cell::get)
    }
}
