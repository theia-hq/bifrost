use std::io;
use std::path::PathBuf;

use bifrost_core::{KeyError, NodeId};

use crate::kind::Kind;
use crate::method::Method;

/// Why a key file could not be loaded, written, adopted, unlocked, or have its locks changed.
///
/// Every variant names the file. None carries key material, and none is ever answered by producing
/// a different key: a refusal is the whole outcome.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file or its directory could not be opened, read, written, synced, or renamed.
    #[error("could not access the key file {}", path.display())]
    Io {
        /// The key file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The path names something other than a regular file: a directory, a pipe, a device.
    #[error("the key file {} is not a regular file", path.display())]
    NotAFile {
        /// The key file.
        path: PathBuf,
    },
    /// Group or other holds a permission bit on the file. The seed IS the node, so loading a file
    /// others can reach would bless the leak.
    #[error(
        "the key file {} gives group or other access (mode {:04o}); run `chmod 600 {}`",
        path.display(),
        mode & 0o7777,
        path.display()
    )]
    Permissive {
        /// The key file.
        path: PathBuf,
        /// The mode that failed the owner-only check.
        mode: u32,
    },
    /// The file is owned by a user who is neither this process's user nor root. A node running as
    /// root would otherwise load a key any user could put at the path.
    #[error(
        "the key file {} is owned by uid {owner}, not by this user or root",
        path.display()
    )]
    Owner {
        /// The key file.
        path: PathBuf,
        /// The uid that owns the file.
        owner: u32,
    },
    /// The bytes are not a key file this build can read.
    #[error("the key file {} is not in a format this build reads", path.display())]
    Format {
        /// The key file.
        path: PathBuf,
        /// What the parser refused.
        #[source]
        source: FormatError,
    },
    /// A lock did not open, or the seed did not open under the key it gave. A wrong passphrase and
    /// damaged contents are deliberately this one variant: the cipher cannot tell them apart, and a
    /// refusal that guessed would be an oracle.
    #[error("could not unlock the key file {}: wrong passphrase, or the file is damaged", path.display())]
    Unlock {
        /// The key file.
        path: PathBuf,
    },
    /// A sealed file unlocked, but its header names a different node than the key it seals.
    #[error("the key file {} names one node in its header and seals the key of another", path.display())]
    Inconsistent {
        /// The key file.
        path: PathBuf,
    },
    /// A write found a file already at the path. A write lands only where nothing is.
    #[error("a key file already exists at {}", path.display())]
    Occupied {
        /// The key file.
        path: PathBuf,
    },
    /// An adopt found a sealed file claiming the adopted key, and was given no passphrase to prove
    /// the claim with. A sealed file's header names its node before it unlocks, but only the unlock
    /// shows the file really holds that key.
    #[error(
        "the key file {} is sealed and claims to hold {claimed}; adopting over it needs its passphrase to prove that",
        path.display()
    )]
    Unconfirmed {
        /// The key file.
        path: PathBuf,
        /// The node the file's header claims, which is also the node the adopt offered.
        claimed: NodeId,
    },
    /// An adopt found a different key already stored at the path.
    #[error("the key file {} already holds {existing}, not {incoming}", path.display())]
    Different {
        /// The key file.
        path: PathBuf,
        /// The node the file already holds; for a sealed file, the node its header claims.
        existing: NodeId,
        /// The node the adopt offered.
        incoming: NodeId,
    },
    /// A write asked to store a root key plain. A root key is only ever written sealed: a plain one is
    /// every device it vouches for in one readable file.
    #[error("a root key is always sealed; {} was not written plain", path.display())]
    PlainRoot {
        /// The key file.
        path: PathBuf,
    },
    /// A lock removal asked to take a root key's passphrase lock. A root key always keeps it: it is
    /// the lock that opens a copy of the file on any machine.
    #[error("a root key always keeps its passphrase lock; {} was not changed", path.display())]
    RootPassphrase {
        /// The key file.
        path: PathBuf,
    },
    /// A lock change found no file to change.
    #[error("there is no key file at {}", path.display())]
    Absent {
        /// The key file.
        path: PathBuf,
    },
    /// The file holds no lock of the method the caller named, to open or to remove. A plain file
    /// holds no lock at all.
    #[error("the key file {} has no {method} lock", path.display())]
    NoLock {
        /// The key file.
        path: PathBuf,
        /// The method the caller named.
        method: Method,
    },
    /// A lock change was given nothing to open the file with, and the file is sealed: only one of its
    /// own locks can open it to change them.
    #[error("the key file {} is sealed; changing its locks needs one of them to open it", path.display())]
    Sealed {
        /// The key file.
        path: PathBuf,
    },
    /// The rewritten file did not read back as the same key, so it was not put in place.
    #[error(
        "the rewritten key file {} did not read back as the same key; the original is unchanged",
        path.display()
    )]
    Unverified {
        /// The key file.
        path: PathBuf,
    },
    /// A lock change found the key file changed or replaced since it read it, and did not write over
    /// it: the old key put back over a new one could destroy the only copy of the new one.
    #[error(
        "the key file {} changed while it was being rewritten; it was left as it now is",
        path.display()
    )]
    Changed {
        /// The key file.
        path: PathBuf,
    },
    /// The filesystem holding the key file has no hard links, which is how a new key file is
    /// published without ever landing over another. FAT and exFAT are such filesystems.
    #[error(
        "the filesystem holding {} cannot publish a key file safely, because it has no hard links",
        path.display()
    )]
    NoHardLinks {
        /// The key file.
        path: PathBuf,
        /// What the filesystem said.
        #[source]
        source: io::Error,
    },
    /// The key file is in place, but its directory could not be synced afterwards, so a power loss
    /// could still undo the change. Not a failed write: loading the file shows the new form.
    #[error(
        "the key file {} was written, but its directory could not be synced to disk",
        path.display()
    )]
    Unsynced {
        /// The key file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// Sealing or unlocking could not run.
    #[error("could not seal or unlock the key file {}", path.display())]
    Crypto {
        /// The key file.
        path: PathBuf,
        /// Which primitive failed.
        #[source]
        source: CryptoError,
    },
}

/// Why a key file's bytes did not parse. Raised by the one parser, before any key is derived, so
/// nothing here depends on a passphrase and nothing here reveals anything about one.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// No sealed-file signature, and not the 32 bytes of a plain seed.
    #[error("the file is {found} bytes, neither a 32-byte plain seed nor a sealed key")]
    Size {
        /// The file's length.
        found: u64,
    },
    /// A sealed-file signature, but the bytes end before its layout does, or run on past it.
    #[error("a sealed key of {found} bytes is truncated or padded")]
    SealedSize {
        /// The file's length.
        found: u64,
    },
    /// A format version this build does not read.
    #[error("sealed key format version {found} is not one this build reads")]
    Version {
        /// The version byte.
        found: u8,
    },
    /// A file kind this build does not know.
    #[error("sealed file kind {found} is not one this build knows")]
    Kind {
        /// The kind byte.
        found: u8,
    },
    /// A sealed file of a known kind, read where the other kind belongs: a device key presented as a
    /// root key, or a root key as a device key.
    #[error("the sealed file is a {found}, not a {expected}")]
    WrongKind {
        /// The kind the reader expected.
        expected: Kind,
        /// The kind the file records.
        found: Kind,
    },
    /// A lock method this build does not know.
    #[error("lock method {found} is not one this build knows")]
    Method {
        /// The method byte.
        found: u8,
    },
    /// A sealed file with no locks: nothing could open it, so it is not a sealed key.
    #[error("the sealed key has no locks")]
    NoLocks,
    /// Two locks of one method. A file holds at most one of each.
    #[error("the sealed key has more than one {method} lock")]
    DuplicateLock {
        /// The method named twice.
        method: Method,
    },
    /// A lock whose body length is not its method's, refused before its body is read.
    #[error("a {method} lock is {} bytes, and this one says {found}", method.body_len())]
    LockLength {
        /// The lock's method.
        method: Method,
        /// The length the record declares.
        found: u16,
    },
    /// A key derivation function this build does not know.
    #[error("key derivation function {found} is not one this build knows")]
    Kdf {
        /// The derivation byte.
        found: u8,
    },
    /// An Argon2id cost outside the accepted bounds, refused before any memory is committed to it.
    #[error(
        "key derivation cost of {memory_kib} KiB, {passes} passes, {lanes} lanes is outside the accepted bounds"
    )]
    Cost {
        /// Memory, in KiB.
        memory_kib: u32,
        /// Passes over memory.
        passes: u32,
        /// Parallel lanes.
        lanes: u32,
    },
    /// The stored public key is not a usable ed25519 identity.
    #[error("the stored public key is not a usable identity")]
    PublicKey(#[source] KeyError),
}

/// Sealing or unlocking a key file could not run: the random source, the key derivation, or the
/// cipher failed.
///
/// Opaque, so the primitives this crate uses stay out of its public surface; the cause is in the
/// `source()` chain.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CryptoError(Primitive);

#[derive(Debug, thiserror::Error)]
enum Primitive {
    #[error("the operating system's random source failed")]
    Entropy(#[source] getrandom::Error),
    #[error("argon2id could not derive a key")]
    Kdf(#[source] argon2::Error),
    #[error("could not allocate the key derivation's working memory")]
    Memory(#[source] std::collections::TryReserveError),
    // The cipher refuses only a key of the wrong length or a message longer than 2^38 bytes, and a
    // 32-byte key and seed are neither. It is a value rather than a panic because this crate does not
    // panic.
    #[error("the cipher could not seal the key")]
    Cipher,
    // A file holds at most one lock per method, so the writer is never handed more than 255 locks.
    // A value rather than a panic for the same reason as `Cipher`.
    #[error("too many locks to seal: a key file holds at most 255")]
    LockCount,
}

impl CryptoError {
    pub(crate) const fn entropy(source: getrandom::Error) -> Self {
        Self(Primitive::Entropy(source))
    }

    pub(crate) const fn kdf(source: argon2::Error) -> Self {
        Self(Primitive::Kdf(source))
    }

    pub(crate) const fn memory(source: std::collections::TryReserveError) -> Self {
        Self(Primitive::Memory(source))
    }

    pub(crate) const fn cipher() -> Self {
        Self(Primitive::Cipher)
    }

    pub(crate) const fn lock_count() -> Self {
        Self(Primitive::LockCount)
    }
}
