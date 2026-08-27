use core::fmt;
use core::str::FromStr;

use data_encoding::BASE32_NOPAD;

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
    /// The four-character wire tag for this suite. Stable across releases.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ed25519 => "bf01",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "bf01" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// A self-certifying node identity: a raw 32-byte public key plus its [`CryptoKind`].
///
/// This is the only way a peer is named in Bifrost. It is self-certifying because a successful
/// transport handshake proves the remote holds the matching private key, so reaching a `NodeId`
/// means reaching exactly that identity with no registry to trust.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId {
    kind: CryptoKind,
    key: [u8; Self::KEY_LEN],
}

impl NodeId {
    /// The length of the raw key material, in bytes.
    pub const KEY_LEN: usize = 32;

    /// Wrap raw key bytes of a known suite.
    pub const fn new(kind: CryptoKind, key: [u8; Self::KEY_LEN]) -> Self {
        Self { kind, key }
    }

    /// The node id an ed25519 secret binds under: its public (verifying) key, tagged
    /// [`CryptoKind::Ed25519`]. This is the same id the iroh and quirk backends derive when they bind the
    /// secret, so it can be computed offline, with no transport stood up, to pre-provision an identity a
    /// machine will later adopt.
    pub fn from_ed25519_secret(secret: &[u8; Self::KEY_LEN]) -> Self {
        let signing = ed25519_dalek::SigningKey::from_bytes(secret);
        Self::new(CryptoKind::Ed25519, signing.verifying_key().to_bytes())
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
        let raw = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(|_| NodeIdParseError::BadEncoding)?;
        let key =
            <[u8; Self::KEY_LEN]>::try_from(raw).map_err(|_| NodeIdParseError::WrongLength)?;
        Ok(Self { kind, key })
    }
}

/// Why a string could not be parsed into a [`NodeId`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NodeIdParseError {
    /// The input was shorter than the four-character suite tag.
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
}
