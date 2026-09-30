//! A lock: one way into a sealed key file. Each lock wraps the file key, and any one of them opens
//! the file.
//!
//! In the file a lock is a record: its method byte, its body's length (two bytes, big-endian), and
//! its body. The method decides the body's shape, and each method's body has one length, so a length
//! is judged against the method before a byte of the body is read.
//!
//! A lock's wrap authenticates the file's first 42 bytes (the signature, version, kind, and public
//! key), its own method byte, and its own body up to the wrapped file key. It does not cover the lock
//! count or any other lock, so adding or removing a lock never disturbs the ones that stay. What binds
//! the list together is the seed's seal, which covers every byte before it (see `envelope`).

pub(crate) mod passphrase;

use zeroize::Zeroizing;

use crate::cipher::KEY_LEN;
use crate::envelope::{HEADER_LEN, Refusal};
use crate::error::{CryptoError, FormatError};
use crate::lock::passphrase::PassphraseLock;
use crate::method::{Method, NewLock, Unlock};

/// Method byte: a passphrase lock.
const METHOD_PASSPHRASE: u8 = 1;

impl Method {
    /// The byte this method is recorded as.
    pub(crate) const fn byte(self) -> u8 {
        match self {
            Self::Passphrase => METHOD_PASSPHRASE,
        }
    }

    /// The method a byte records, or `None` for a byte no method is registered at.
    pub(crate) const fn of_byte(byte: u8) -> Option<Self> {
        match byte {
            METHOD_PASSPHRASE => Some(Self::Passphrase),
            _ => None,
        }
    }

    /// The one length this method's body has. A record declaring any other is refused before its
    /// body is read, so a hostile length costs nothing.
    pub(crate) const fn body_len(self) -> u16 {
        match self {
            Self::Passphrase => passphrase::BODY_LEN as u16,
        }
    }
}

// A body length is two bytes on disk.
const _: () = assert!(passphrase::BODY_LEN <= u16::MAX as usize);

/// The random key that seals a file's seed, and that every lock wraps.
///
/// Drawn once, when a file is first sealed, and kept for the file's life: adding or removing a lock
/// re-wraps this same key, so it needs one unlock by any lock the file already holds. Rotating it
/// would guard nothing, because whoever opened any copy of the file already holds the seed.
///
/// Boxed like [`Secret`](crate::Secret), because it opens the seed from any copy of the file: a move
/// copies the pointer, never the key, so no unwiped copy is left in a dead stack slot.
pub(crate) struct FileKey(Box<Zeroizing<[u8; KEY_LEN]>>);

impl FileKey {
    /// A fresh file key from the operating system's random source, written straight into its heap
    /// home.
    pub(crate) fn generate() -> Result<Self, CryptoError> {
        let mut key = Self::zeroed();
        getrandom::fill(&mut key.0[..]).map_err(CryptoError::entropy)?;
        Ok(key)
    }

    /// A file key holding a copy of `bytes`, for an unwrap, whose source buffer wipes itself.
    pub(crate) fn copy_of(bytes: &[u8; KEY_LEN]) -> Self {
        let mut key = Self::zeroed();
        key.0.copy_from_slice(bytes);
        key
    }

    fn zeroed() -> Self {
        Self(Box::new(Zeroizing::new([0; KEY_LEN])))
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// One parsed lock. Exhaustive like [`Method`]: a method added later is a compile error here first.
pub(crate) enum Lock {
    /// A passphrase lock.
    Passphrase(PassphraseLock),
}

impl Lock {
    /// Parse a lock's body. The caller has already read the method and checked the body's length
    /// against it.
    pub(crate) fn parse(method: Method, body: &[u8]) -> Result<Self, FormatError> {
        match method {
            Method::Passphrase => {
                let Ok(body) = body.try_into() else {
                    // Unreachable: the caller judged the declared length before reading the body.
                    // A refusal rather than a panic because this crate does not panic, and the body
                    // was read under a two-byte length, so its length fits in one.
                    return Err(FormatError::LockLength {
                        method,
                        found: u16::try_from(body.len()).unwrap_or(u16::MAX),
                    });
                };
                PassphraseLock::parse(body).map(Self::Passphrase)
            }
        }
    }

    /// Wrap `file_key` under a new lock, for a file whose first bytes are `header`.
    pub(crate) fn wrap(
        new: NewLock<'_>,
        file_key: &FileKey,
        header: &[u8; HEADER_LEN],
    ) -> Result<Self, CryptoError> {
        match new {
            NewLock::Passphrase(passphrase) => {
                PassphraseLock::wrap(passphrase, file_key, header).map(Self::Passphrase)
            }
        }
    }

    /// The method this lock opens with.
    pub(crate) const fn method(&self) -> Method {
        match self {
            Self::Passphrase(_) => Method::Passphrase,
        }
    }

    /// Unwrap the file key with `with`, which the caller has matched to this lock's method.
    pub(crate) fn open(
        &self,
        with: Unlock<'_>,
        header: &[u8; HEADER_LEN],
    ) -> Result<FileKey, Refusal> {
        match (self, with) {
            (Self::Passphrase(lock), Unlock::Passphrase(passphrase)) => {
                lock.open(passphrase, header)
            }
        }
    }

    /// Append this lock's record to `image`: method, body length, body.
    pub(crate) fn write(&self, image: &mut Vec<u8>) {
        image.push(self.method().byte());
        image.extend_from_slice(&self.method().body_len().to_be_bytes());
        match self {
            Self::Passphrase(lock) => image.extend_from_slice(&lock.body()),
        }
    }
}

/// The associated data a lock's wrap authenticates: the file's first bytes, the lock's method byte,
/// and its body up to the wrapped file key (`head`).
fn wrap_aad(header: &[u8; HEADER_LEN], method: Method, head: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + 1 + head.len());
    aad.extend_from_slice(header);
    aad.push(method.byte());
    aad.extend_from_slice(head);
    aad
}
