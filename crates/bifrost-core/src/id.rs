use core::fmt;
use core::str::FromStr;

use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

/// The cryptographic suite a [`NodeId`] belongs to.
///
/// A node identity is a raw public key, but we tag it with a suite version so the cryptosystem can
/// migrate without a flag day: a future suite is a new variant, and every `match` is forced to
/// acknowledge it. The tag travels with the key everywhere, so a peer never has to guess the suite.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CryptoKind {
    /// ed25519 identity with x25519 agreement, over QUIC and TLS 1.3. The v0 default.
    Ed25519,
}

impl CryptoKind {
    /// The suite tag at the front of a key's text (`ed01` is Ed25519). Stable across releases; the key
    /// text format is the tag, then the key in RFC 4648 base32, lowercase, unpadded.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed01",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            t if t.eq_ignore_ascii_case("ed01") => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// A self-certifying node identity: a checked 32-byte public key plus its [`CryptoKind`].
///
/// This is the only way a peer is named in Bifrost. Every `NodeId` passed [`try_new`](Self::try_new)'s
/// check or was derived from a secret, so it is never a small-order point, a non-canonical encoding, or
/// a torsioned twin of another identity. Whether reaching a `NodeId` proves the peer holds its key is
/// the transport's security profile, not a property of the type: a `Sealed` transport proves it, an
/// `Announced` one reaches whatever key answers. Consumers that need proof require the `PeerProven` bound.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId {
    kind: CryptoKind,
    key: [u8; Self::KEY_LEN],
}

impl NodeId {
    /// The length of the raw key material, in bytes.
    pub const KEY_LEN: usize = 32;

    /// The node id these bytes name, or why they do not name one.
    ///
    /// There is no unchecked constructor: a `NodeId` exists only if its bytes are the canonical encoding
    /// of a prime-order point. The check does not make an identity unique: the negation `-A` of an
    /// identity `A` passes it, and the holder of `A`'s secret can sign for both. Identities compare by
    /// exact bytes, so the two are different identities.
    pub fn try_new(kind: CryptoKind, key: [u8; Self::KEY_LEN]) -> Result<Self, KeyError> {
        match kind {
            CryptoKind::Ed25519 => check_ed25519_identity(&key)?,
        }
        Ok(Self { kind, key })
    }

    /// The node id an ed25519 secret binds under: its public (verifying) key, tagged
    /// [`CryptoKind::Ed25519`]. This is the same id the iroh and quirk backends derive when they bind the
    /// secret, so it can be computed offline, with no transport stood up, to pre-provision an identity a
    /// machine will later adopt.
    ///
    /// Infallible: a secret's public key always passes [`try_new`](Self::try_new)'s check.
    pub fn from_ed25519_secret(secret: &[u8; Self::KEY_LEN]) -> Self {
        let signing = ed25519_dalek::SigningKey::from_bytes(secret);
        Self {
            kind: CryptoKind::Ed25519,
            key: signing.verifying_key().to_bytes(),
        }
    }

    /// The node id of a *device* identity derived from a root secret and a label.
    ///
    /// The owner holds `root` and can compute any device's id offline from `(root, label)`: instant
    /// addressing with no registry and no network round-trip. The machine adopts the matching child
    /// secret (see [`derive_ed25519_child_secret`]) and binds under it, so it comes up *as* this id.
    ///
    /// Derivation is *hardened*: the child mixes the root SECRET, so only the owner (who holds `root`)
    /// can compute or predict a child. ed25519 has no sound public (secret-free) derivation, so we do
    /// not pretend to offer lineage a third party can check from public keys alone; that is a
    /// non-requirement here, because the only party who must recognize a device as yours is your own
    /// gate, and it does so because you derived the device and put it in your family set.
    pub fn derive_ed25519(root: &[u8; Self::KEY_LEN], label: &str) -> Self {
        Self::from_ed25519_secret(&derive_ed25519_child_secret(root, label))
    }

    /// The cryptographic suite this identity belongs to.
    pub const fn kind(self) -> CryptoKind {
        self.kind
    }

    /// The raw public key bytes.
    pub const fn key(&self) -> &[u8; Self::KEY_LEN] {
        &self.key
    }

    /// A short, human-glanceable prefix for logs. Not a stable or complete identifier.
    pub fn short(&self) -> String {
        self.to_string().chars().take(16).collect()
    }
}

/// Why 32 bytes are not a usable ed25519 identity: the first check they fail, in the order below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The bytes do not decompress to a point on the ed25519 curve.
    #[error("not a point on the ed25519 curve")]
    NotOnCurve,
    /// A valid point, in an encoding other than the one it compresses to.
    #[error("non-canonical encoding of a valid point")]
    NotCanonical,
    /// A point of order 8 or less: no secret key has it as its public key, and a Diffie-Hellman
    /// agreement with it is all zeros, which anyone can compute.
    #[error("a small-order point: no secret key has it as its public key")]
    SmallOrder,
    /// A prime-order point plus a torsion component: a torsioned twin of another identity, whose holder
    /// can sign for it.
    #[error("carries a torsion component: the holder of another key can sign for it")]
    HasTorsion,
}

/// Check that 32 bytes name an ed25519 identity somebody could hold, cheapest clause first.
///
/// `from_bytes` only decompresses, so the canonical clause is ours: it re-compresses the point and
/// refuses any input that is not the spelling the point compresses to.
fn check_ed25519_identity(key: &[u8; NodeId::KEY_LEN]) -> Result<(), KeyError> {
    let point = ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| KeyError::NotOnCurve)?
        .to_edwards();
    if point.compress().to_bytes() != *key {
        return Err(KeyError::NotCanonical);
    }
    if point.is_small_order() {
        return Err(KeyError::SmallOrder);
    }
    if !point.is_torsion_free() {
        return Err(KeyError::HasTorsion);
    }
    Ok(())
}

/// The child ed25519 secret derived from a root secret and a label: a domain-separated BLAKE3 KDF over
/// the root, keyed on the label. This is the identity a machine ADOPTS to become
/// [`NodeId::derive_ed25519(root, label)`], the derived-key payload it is provisioned with.
///
/// The KDF context binds both the purpose and the label, and the root is the key material, so a device
/// seed and any other domain-separated derivation over the same root (one keyed on a different context)
/// never coincide, and two distinct labels never collide. Any 32 bytes is a valid ed25519 seed (the
/// scalar is hashed and clamped internally by [`ed25519_dalek::SigningKey`]), so the KDF output is used
/// directly with no rejection. Hardened: recovering or predicting a child needs the root secret.
///
/// The child is as secret as the root, so it is returned in a [`Zeroizing`] owner: it is wiped
/// wherever it is finally dropped, and a caller has to copy it out on purpose to leave it unwiped.
pub fn derive_ed25519_child_secret(
    root: &[u8; NodeId::KEY_LEN],
    label: &str,
) -> Zeroizing<[u8; NodeId::KEY_LEN]> {
    Zeroizing::new(blake3::derive_key(
        &format!("bifrost device identity v1: {label}"),
        root,
    ))
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.kind.tag(),
            BASE32_NOPAD.encode(&self.key).to_lowercase()
        )
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({self})")
    }
}

impl FromStr for NodeId {
    type Err = NodeIdParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (tag, encoded) = text.split_at_checked(4).ok_or(NodeIdParseError::TooShort)?;
        let kind = CryptoKind::from_tag(tag).ok_or(NodeIdParseError::UnknownSuite)?;
        // Case folding is ASCII-only and any non-ASCII input is refused first: a Unicode fold maps some
        // non-ASCII letters onto ASCII ones (`ſ` to `S`, `ı` to `I`), which would let text that is not
        // the key's text decode to the same bytes.
        if !encoded.is_ascii() {
            return Err(NodeIdParseError::BadEncoding);
        }
        let raw = BASE32_NOPAD
            .decode(encoded.to_ascii_uppercase().as_bytes())
            .map_err(|_| NodeIdParseError::BadEncoding)?;
        let key =
            <[u8; Self::KEY_LEN]>::try_from(raw).map_err(|_| NodeIdParseError::WrongLength)?;
        Self::try_new(kind, key).map_err(NodeIdParseError::Key)
    }
}

/// Why a string could not be parsed into a [`NodeId`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeIdParseError {
    /// The input was shorter than the suite tag.
    #[error("identity string too short")]
    TooShort,
    /// The suite tag was not recognized.
    #[error("unknown crypto suite tag")]
    UnknownSuite,
    /// The key body was not valid base32.
    #[error("invalid base32 encoding")]
    BadEncoding,
    /// The decoded key was not the expected length.
    #[error("wrong key length")]
    WrongLength,
    /// The decoded bytes are not a usable ed25519 identity.
    #[error("not a usable identity")]
    Key(#[source] KeyError),
}
