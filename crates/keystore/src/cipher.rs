//! The one cipher in the format: XChaCha20-Poly1305 over a 32-byte secret, the seed under the file
//! key and the file key under each lock. One function each way, so both seals are the same code.

use chacha20poly1305::aead::{AeadInPlace as _, KeyInit as _};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// A cipher key, and the secret every seal here carries: an ed25519 seed or a file key.
pub(crate) const KEY_LEN: usize = 32;
/// An XChaCha20-Poly1305 nonce: 24 bytes, drawn at random, so no two seals under one key share one.
pub(crate) const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// A sealed secret: the encrypted 32 bytes, then the Poly1305 tag.
pub(crate) const SEALED_LEN: usize = KEY_LEN + TAG_LEN;

/// Seal `secret` under `key`, authenticating `aad` with it.
pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    secret: &[u8; KEY_LEN],
) -> Result<[u8; SEALED_LEN], CryptoError> {
    // Encrypt in a wiping buffer: if sealing fails partway, the plaintext must not be left in a plain
    // array on its way out of scope.
    let mut text = Zeroizing::new(*secret);
    // Built from arrays and the checked slice constructor, never `from_slice`, which newer releases
    // of the array crate deprecate and a consumer's lock may resolve to.
    let tag = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::cipher())?
        .encrypt_in_place_detached(&XNonce::from(*nonce), aad, &mut text[..])
        .map_err(|_| CryptoError::cipher())?;
    let mut sealed = [0; SEALED_LEN];
    sealed[..KEY_LEN].copy_from_slice(&text[..]);
    sealed[KEY_LEN..].copy_from_slice(&tag);
    Ok(sealed)
}

/// Why a seal did not open.
pub(crate) enum Failed {
    /// The tag did not verify: the wrong key, or damaged bytes. The cipher cannot tell them apart.
    Tag,
    /// The cipher could not run.
    Crypto(CryptoError),
}

/// Open what [`seal`] made with the same key, nonce, and `aad`.
pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8; SEALED_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Failed> {
    let mut text = Zeroizing::new([0; KEY_LEN]);
    text.copy_from_slice(&sealed[..KEY_LEN]);
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(&sealed[KEY_LEN..]);
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Failed::Crypto(CryptoError::cipher()))?
        .decrypt_in_place_detached(&XNonce::from(*nonce), aad, &mut text[..], &Tag::from(tag))
        .map_err(|_| Failed::Tag)?;
    Ok(text)
}
