//! The key file format: the one parser, and the writer beside it.
//!
//! A key file is one of two shapes, told apart by its first eight bytes:
//!
//! - **plain**: exactly the 32-byte ed25519 seed, nothing else;
//! - **sealed**: [`SIGNATURE`], then a version byte that governs everything after it. Version 2 is a
//!   random file key that seals the seed, and a list of locks, each wrapping that file key. Any one
//!   lock opens the file. Integers are big-endian:
//!
//! | offset | len | field                                                            |
//! | ------ | --- | ---------------------------------------------------------------- |
//! | 0      | 8   | signature `KEYSTORE`                                             |
//! | 8      | 1   | format version, `2`                                              |
//! | 9      | 1   | file kind, `1` = a device key, `2` = a root key                  |
//! | 10     | 32  | the seed's ed25519 public key, so a locked file names its node   |
//! | 42     | 1   | lock count `n`, at least 1                                       |
//! | 43     | ..  | `n` locks, each: method (1), body length (2), body               |
//! | ..     | 24  | XChaCha20-Poly1305 nonce                                         |
//! | ..     | 48  | the seed, encrypted under the file key, then its Poly1305 tag    |
//!
//! Every byte before the seed's nonce is the seed seal's associated data, exactly as it sits in the
//! file: a lock swapped, dropped, reordered, or edited fails the whole file, not only that lock. The
//! version, kind, and method bytes are where the format grows: a new value is a new meaning, and an
//! unknown value is refused by name, never guessed at. Each lock's own layout is in `lock`.
//!
//! A file holds at most one lock per method, so the list is bounded by the methods this build knows,
//! and every length in it is judged before the bytes it covers are read.
//!
//! The kind says what the key is FOR, and a file is only ever read as the kind its reader expects: a
//! sealed device key presented where a root key belongs is refused by its kind, and so is the reverse.
//! Both kinds carry an ed25519 seed under the same layout; only the byte, which every seal
//! authenticates, tells them apart. A plain file has no header and so no kind: it is the seed and
//! nothing else.

use bifrost_core::{CryptoKind, NodeId};

use crate::cipher::{self, Failed, NONCE_LEN, SEALED_LEN};
use crate::error::{CryptoError, FormatError};
use crate::kind::Kind;
use crate::lock::{FileKey, Lock};
use crate::method::{Method, NewLock, Unlock};
use crate::secret::{SEED_LEN, Secret};

/// Every sealed key file opens with these bytes, at every version, forever.
///
/// Eight bytes rather than a four-byte wire magic, because a sealed file shares its namespace with a
/// plain one, and a plain file is 32 uniformly random bytes: at eight, the chance that a seed someone
/// already holds happens to open with the signature (and would then be refused as a damaged sealed
/// file) is one in 2^64, where four would make it one in 2^32. The version lives in its own byte for
/// the same reason: the signature never changes, so it can never collide with itself.
pub(crate) const SIGNATURE: [u8; 8] = *b"KEYSTORE";

/// The one format version this build reads and writes.
const VERSION: u8 = 2;
/// File kind: a device's own ed25519 key file. A backup of one is this same kind, byte for byte a sealed
/// key file for the same node, so restoring it is installing a copy that was already verified. An
/// artifact that is NOT a device key file takes a new kind, so it can never be mistaken for one.
const KIND_DEVICE_KEY: u8 = 1;
/// File kind: a root key, the key other keys are vouched for by. The same layout as a device key, told
/// apart by this byte alone, so neither can be read in the other's place.
const KIND_ROOT_KEY: u8 = 2;

impl Kind {
    /// The byte this kind is recorded as.
    const fn byte(self) -> u8 {
        match self {
            Self::Device => KIND_DEVICE_KEY,
            Self::Root => KIND_ROOT_KEY,
        }
    }

    /// The kind a byte records, or `None` for a byte no kind is registered at.
    const fn of_byte(byte: u8) -> Option<Self> {
        match byte {
            KIND_DEVICE_KEY => Some(Self::Device),
            KIND_ROOT_KEY => Some(Self::Root),
            _ => None,
        }
    }
}

// The header's offsets, in file order. Every field is fixed-width, so these ARE the grammar.
const AT_VERSION: usize = SIGNATURE.len();
const AT_KIND: usize = AT_VERSION + 1;
pub(crate) const AT_PUBLIC: usize = AT_KIND + 1;
/// The file's first bytes, which every lock's wrap authenticates. The lock count follows, and is
/// deliberately outside: a lock stays valid as others are added or removed.
pub(crate) const HEADER_LEN: usize = AT_PUBLIC + NodeId::KEY_LEN;
/// The lock count.
pub(crate) const AT_COUNT: usize = HEADER_LEN;
/// The first lock's record.
pub(crate) const AT_LOCKS: usize = AT_COUNT + 1;

// The layout is frozen: a file written today must parse forever. Moving a field is a compile error
// here before it is a golden-vector failure in the tests.
const _: () = assert!(HEADER_LEN == 42 && AT_LOCKS == 43);

/// What the one parser found in a key file's bytes.
pub(crate) enum Parsed<'a> {
    /// A plain file: the seed itself, borrowed from the caller's wiping buffer.
    Plain(&'a [u8; SEED_LEN]),
    /// A sealed file, structurally sound and within bounds, not yet unlocked.
    Sealed(Envelope),
}

/// Parse a key file's bytes, read where a key of `expected` kind belongs: the only place a key file is
/// interpreted.
///
/// The signature decides the shape first, so a sealed file cut down to 32 bytes is refused as a
/// damaged sealed file and never read as a plain seed (that would silently become a different key). A
/// sealed file of the other kind is refused by its kind.
pub(crate) fn parse(bytes: &[u8], expected: Kind) -> Result<Parsed<'_>, FormatError> {
    if bytes.starts_with(&SIGNATURE) {
        return Envelope::parse(bytes, expected).map(Parsed::Sealed);
    }
    <&[u8; SEED_LEN]>::try_from(bytes)
        .map(Parsed::Plain)
        .map_err(|_| FormatError::Size {
            found: bytes.len() as u64,
        })
}

/// A sealed key file, parsed: every structural byte checked, every lock parsed and within bounds, and
/// the bytes the seed's seal covers kept exactly as read, so they authenticate as they sit in the
/// file.
pub(crate) struct Envelope {
    header: [u8; HEADER_LEN],
    node_id: NodeId,
    /// In file order, at most one per method.
    locks: Vec<Lock>,
    /// Every byte before the seed's nonce: the seed seal's associated data.
    covered: Vec<u8>,
    seed_nonce: [u8; NONCE_LEN],
    sealed_seed: [u8; SEALED_LEN],
}

/// A sealed file opened: the seed, and the file key a lock change re-wraps.
pub(crate) struct Opened {
    pub(crate) secret: Secret,
    pub(crate) file_key: FileKey,
}

impl Envelope {
    fn parse(bytes: &[u8], expected: Kind) -> Result<Self, FormatError> {
        // The version governs everything after it, so it is read before any length is judged: a file
        // from another version is named as that, not as a damaged version 2 file.
        let Some(&version) = bytes.get(AT_VERSION) else {
            return Err(sealed_size(bytes));
        };
        if version != VERSION {
            return Err(FormatError::Version { found: version });
        }
        let mut reader = Reader { bytes, at: 0 };
        let header: [u8; HEADER_LEN] = reader.array()?;
        match Kind::of_byte(header[AT_KIND]) {
            Some(found) if found == expected => {}
            Some(found) => return Err(FormatError::WrongKind { expected, found }),
            None => {
                return Err(FormatError::Kind {
                    found: header[AT_KIND],
                });
            }
        }
        // The stored public half names the node while the file is locked, so it is parsed like any key
        // that enters from outside: a file cannot name an identity nobody could hold.
        let mut public = [0; NodeId::KEY_LEN];
        public.copy_from_slice(&header[AT_PUBLIC..]);
        let node_id =
            NodeId::try_new(CryptoKind::Ed25519, public).map_err(FormatError::PublicKey)?;

        let count = reader.byte()?;
        if count == 0 {
            return Err(FormatError::NoLocks);
        }
        // The count needs no bound of its own: each lock must name a method this build knows, and no
        // method twice, so a list longer than the methods refuses at its first extra lock, before
        // anything past that lock's method byte is read. A root's passphrase lock needs no check here
        // while the passphrase is the only method: any list of at least one known lock holds it.
        let mut locks: Vec<Lock> = Vec::new();
        for _ in 0..count {
            let found = reader.byte()?;
            let Some(method) = Method::of_byte(found) else {
                return Err(FormatError::Method { found });
            };
            if locks.iter().any(|lock| lock.method() == method) {
                return Err(FormatError::DuplicateLock { method });
            }
            let length = u16::from_be_bytes(reader.array()?);
            if length != method.body_len() {
                return Err(FormatError::LockLength {
                    method,
                    found: length,
                });
            }
            locks.push(Lock::parse(method, reader.take(usize::from(length))?)?);
        }
        let covered = reader.consumed().to_vec();
        let seed_nonce = reader.array()?;
        let sealed_seed = reader.array()?;
        if !reader.is_done() {
            return Err(sealed_size(bytes));
        }
        Ok(Self {
            header,
            node_id,
            locks,
            covered,
            seed_nonce,
            sealed_seed,
        })
    }

    /// Seal `secret` as a key of `kind` under one new lock: a fresh file key, and a fresh nonce for the
    /// seed.
    pub(crate) fn seal(
        secret: &Secret,
        kind: Kind,
        lock: NewLock<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        let file_key = FileKey::generate()?;
        let header = header(kind, secret.node_id());
        let lock = Lock::wrap(lock, &file_key, &header)?;
        assemble(&header, &[lock], &file_key, secret, &fresh_nonce()?)
    }

    /// Open the file with `with`: its lock unwraps the file key, and the file key opens the seed. The
    /// file must hold a lock of `with`'s method.
    pub(crate) fn unlock(&self, with: Unlock<'_>) -> Result<Opened, Refusal> {
        let Some(lock) = self.lock(with.method()) else {
            return Err(Refusal::NoLock(with.method()));
        };
        let file_key = lock.open(with, &self.header)?;
        let secret = self.open_with(&file_key)?;
        Ok(Opened { secret, file_key })
    }

    /// Open the seed with a file key already in hand, and hold it to the header's node.
    pub(crate) fn open_with(&self, file_key: &FileKey) -> Result<Secret, Refusal> {
        let seed = match cipher::open(
            file_key.bytes(),
            &self.seed_nonce,
            &self.covered,
            &self.sealed_seed,
        ) {
            Ok(seed) => seed,
            Err(Failed::Tag) => return Err(Refusal::Unlock),
            Err(Failed::Crypto(source)) => return Err(Refusal::Crypto(source)),
        };
        let secret = Secret::copy_of(&seed);
        // The header's public key is authenticated, but only a writer holding the file key could have
        // put a mismatched one there. A locked file must never name a node it would not unlock into,
        // so the mismatch is refused rather than trusted either way.
        if secret.node_id() != self.node_id {
            return Err(Refusal::Inconsistent);
        }
        Ok(secret)
    }

    /// This file with `new` wrapping its file key: in place of the lock of the same method if there is
    /// one (how a passphrase is changed), else after the others. The seed is sealed again under the
    /// same file key with a fresh nonce, because its seal covers the list.
    pub(crate) fn with_lock(
        &self,
        opened: &Opened,
        new: NewLock<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        let new = Lock::wrap(new, &opened.file_key, &self.header)?;
        let mut locks: Vec<&Lock> = self.locks.iter().collect();
        match locks.iter().position(|lock| lock.method() == new.method()) {
            Some(at) => locks[at] = &new,
            None => locks.push(&new),
        }
        assemble(
            &self.header,
            locks,
            &opened.file_key,
            &opened.secret,
            &fresh_nonce()?,
        )
    }

    /// This file without its lock of `method`, or `None` when that is its last lock, and so nothing
    /// sealed remains to write.
    pub(crate) fn without_lock(
        &self,
        opened: &Opened,
        method: Method,
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        let locks: Vec<&Lock> = self
            .locks
            .iter()
            .filter(|lock| lock.method() != method)
            .collect();
        if locks.is_empty() {
            return Ok(None);
        }
        assemble(
            &self.header,
            locks,
            &opened.file_key,
            &opened.secret,
            &fresh_nonce()?,
        )
        .map(Some)
    }

    /// The methods of this file's locks, in file order, read without unlocking.
    pub(crate) fn methods(&self) -> impl Iterator<Item = Method> + '_ {
        self.locks.iter().map(Lock::method)
    }

    /// Whether this file holds a lock of `method`.
    pub(crate) fn holds(&self, method: Method) -> bool {
        self.lock(method).is_some()
    }

    fn lock(&self, method: Method) -> Option<&Lock> {
        self.locks.iter().find(|lock| lock.method() == method)
    }

    /// The node this file seals, read from the header without unlocking.
    pub(crate) const fn node_id(&self) -> NodeId {
        self.node_id
    }
}

/// Why a parsed envelope did not unlock. The key file attaches its path to each.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// Wrong passphrase, or the file was damaged: deliberately one case.
    Unlock,
    /// The seal opened, but the header names a different key.
    Inconsistent,
    /// The file holds no lock of this method.
    NoLock(Method),
    /// A primitive could not run.
    Crypto(CryptoError),
}

/// The file's first bytes for a key of `kind` whose public key is `public`.
pub(crate) fn header(kind: Kind, public: NodeId) -> [u8; HEADER_LEN] {
    let mut header = [0; HEADER_LEN];
    header[..AT_VERSION].copy_from_slice(&SIGNATURE);
    header[AT_VERSION] = VERSION;
    header[AT_KIND] = kind.byte();
    header[AT_PUBLIC..].copy_from_slice(public.key());
    header
}

/// A sealed file's bytes: `header`, the lock list, and `secret` sealed under `file_key` over both.
pub(crate) fn assemble<'a>(
    header: &[u8; HEADER_LEN],
    locks: impl IntoIterator<Item = &'a Lock>,
    file_key: &FileKey,
    secret: &Secret,
    seed_nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let mut image = header.to_vec();
    image.push(0);
    let mut count: u8 = 0;
    for lock in locks {
        lock.write(&mut image);
        // At most one lock per method, and a method is one byte, so the count fits in one.
        count = count.saturating_add(1);
    }
    image[AT_COUNT] = count;
    let sealed =
        secret.with_bytes(|seed| cipher::seal(file_key.bytes(), seed_nonce, &image, seed))?;
    image.extend_from_slice(seed_nonce);
    image.extend_from_slice(&sealed);
    Ok(image)
}

fn fresh_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(CryptoError::entropy)?;
    Ok(nonce)
}

fn sealed_size(bytes: &[u8]) -> FormatError {
    FormatError::SealedSize {
        found: bytes.len() as u64,
    }
}

/// A cursor over a sealed file's bytes. Every read is bounded by what is there: a file that ends
/// before its layout does is refused by its size, never read past.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], FormatError> {
        let taken = self
            .at
            .checked_add(len)
            .and_then(|end| self.bytes.get(self.at..end))
            .ok_or_else(|| sealed_size(self.bytes))?;
        self.at += len;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, FormatError> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// Everything read so far.
    fn consumed(&self) -> &'a [u8] {
        self.bytes.get(..self.at).unwrap_or_default()
    }

    fn is_done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

#[cfg(test)]
#[path = "envelope_tests.rs"]
mod envelope_tests;
