use core::fmt;

use bifrost_core::NodeId;
use zeroize::{Zeroize as _, ZeroizeOnDrop};

use crate::error::CryptoError;

/// The length of an ed25519 seed, which is also the length of a plain key file.
pub(crate) const SEED_LEN: usize = NodeId::KEY_LEN;

/// An ed25519 seed: the one secret a node holds.
///
/// The bytes live behind a heap pointer and are wiped when the `Secret` drops, so moving a `Secret`
/// moves a pointer and leaves no copy of the seed behind in the frame it left. There is deliberately
/// no way to take the seed out by value: no `into_bytes`, no `to_bytes`, no `Clone`, no `Deref`, no
/// `AsRef`. A consumer that needs the raw bytes borrows them for the length of a closure
/// ([`with_bytes`](Self::with_bytes)). One that must hold them across an `.await` holds the `Secret`
/// instead, and passes the borrow to something that takes what it needs before its future starts
/// (the transport binds do).
///
/// Each refusal below names the error it must fail with, so it fails for the reason it states and
/// not for a typo. Only a nightly `rustdoc` checks the codes; a stable one checks only that the
/// example fails to compile.
///
/// ```compile_fail,E0599
/// # fn escape(secret: keystore::Secret) -> [u8; 32] {
/// secret.into_bytes()
/// # }
/// ```
///
/// `clone` resolves to `<&Secret as Clone>`, which returns the reference, not a `Secret`:
///
/// ```compile_fail,E0308
/// # fn escape(secret: &keystore::Secret) -> keystore::Secret {
/// secret.clone()
/// # }
/// ```
///
/// ```compile_fail,E0614
/// # fn escape(secret: &keystore::Secret) -> [u8; 32] {
/// **secret
/// # }
/// ```
///
/// ```compile_fail,E0599
/// # fn escape(secret: &keystore::Secret) -> &[u8] {
/// secret.as_ref()
/// # }
/// ```
///
/// ```compile_fail,E0599
/// # fn escape(secret: &keystore::Secret) -> zeroize::Zeroizing<[u8; 32]> {
/// secret.to_bytes()
/// # }
/// ```
///
/// The same shape through the sanctioned door compiles, so each refusal above is the missing escape
/// and not a typo:
///
/// ```
/// # fn lend(secret: &keystore::Secret) -> usize {
/// secret.with_bytes(|seed| seed.len())
/// # }
/// ```
pub struct Secret(Box<[u8; SEED_LEN]>);

impl Secret {
    /// A fresh seed drawn from the operating system's random source, written straight into its heap
    /// home so no stack copy of it exists. Fallible rather than panicking: a machine whose random
    /// source fails must not be handed a key.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut secret = Self::zeroed();
        getrandom::fill(&mut secret.0[..]).map_err(CryptoError::entropy)?;
        Ok(secret)
    }

    /// Take the seed out of `seed`, wiping the caller's array once it is copied in. This is how a
    /// seed that arrived some other way (decoded from a provisioning token, say) becomes a `Secret`
    /// without a second unwiped copy surviving at the call site.
    pub fn take(seed: &mut [u8; SEED_LEN]) -> Self {
        let secret = Self::copy_of(seed);
        seed.zeroize();
        secret
    }

    /// A `Secret` holding a copy of `seed`, for the loader, whose source buffer wipes itself.
    pub(crate) fn copy_of(seed: &[u8; SEED_LEN]) -> Self {
        let mut secret = Self::zeroed();
        secret.0.copy_from_slice(seed);
        secret
    }

    fn zeroed() -> Self {
        Self(Box::new([0; SEED_LEN]))
    }

    /// The node id this seed binds under: its ed25519 public key. Computed from the seed, never
    /// stored beside it, so the two cannot disagree.
    pub fn node_id(&self) -> NodeId {
        NodeId::from_ed25519_secret(&self.0)
    }

    /// Lend the raw seed to `lend` for the length of the call. The borrow cannot outlive the closure,
    /// so the only copy that can escape is one the caller makes on purpose.
    pub fn with_bytes<R>(&self, lend: impl FnOnce(&[u8; SEED_LEN]) -> R) -> R {
        lend(&self.0)
    }
}

/// Wipes the seed where it lives, on the heap, before the allocation is freed.
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret {}

/// Names the key, never shows it: the node id is public, the seed is not.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret").field(&self.node_id()).finish()
    }
}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod secret_tests;
