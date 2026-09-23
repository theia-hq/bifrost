//! Storage for a node's secret key: one [`Secret`], one versioned file format, and the four codecs
//! that load, write, adopt, and migrate a key file.
//!
//! A key file holds one ed25519 seed under one [`Method`]: `plain`, the raw 32-byte seed, or
//! `passphrase`, the seed sealed under a passphrase. The method is a property of the FILE. It is read
//! from the file's own bytes, never from configuration, and it changes only when [`KeyFile::migrate`]
//! rewrites the file. [`KeyFile::load`] states which case it found (nothing there, a plain key, a
//! locked key) or why it refuses, and it never returns a key the file does not hold.
//!
//! This crate stores and unlocks; it decides nothing else. Where a key file lives, whether an absent
//! one should be created, how a passphrase is obtained from a person, and what the key signs all
//! belong to the caller. That split is enforced by what the crate depends on, and pinned by its tests.
//!
//! The secret itself never leaves a [`Secret`] by value: it is lent out through a borrow
//! ([`Secret::with_bytes`]), and every buffer that holds it here is wiped on drop. What this cannot
//! stop is a copy the caller makes on purpose: a seed is a `Copy` array, so
//! `secret.with_bytes(|seed| *seed)` compiles to a bare `[u8; 32]` that nothing wipes. Hand the borrow
//! on instead: the transport binds take `&[u8; 32]`, so `secret.with_bytes(bind)` makes no copy.

mod envelope;
mod error;
mod key_file;
mod method;
mod passphrase;
mod secret;
mod stored;
#[cfg(unix)]
mod uid;

pub use error::{CryptoError, Error, FormatError};
pub use key_file::KeyFile;
pub use method::{Method, Protection};
pub use passphrase::{Passphrase, PassphraseError};
pub use secret::Secret;
pub use stored::{Locked, Stored};

#[cfg(test)]
mod test_dir;
