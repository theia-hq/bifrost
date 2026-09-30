//! The passphrase lock: Argon2id derives a key from the passphrase, and XChaCha20-Poly1305 wraps the
//! file key under it.
//!
//! Its body is 101 bytes, every field fixed-width, integers big-endian:
//!
//! | offset | len | field                                                   |
//! | ------ | --- | ------------------------------------------------------- |
//! | 0      | 1   | key derivation function, `1` = Argon2id, version `0x13` |
//! | 1      | 4   | Argon2id memory, KiB                                    |
//! | 5      | 4   | Argon2id passes                                         |
//! | 9      | 4   | Argon2id lanes                                          |
//! | 13     | 16  | salt                                                    |
//! | 29     | 24  | XChaCha20-Poly1305 nonce                                |
//! | 53     | 48  | the file key, encrypted, then its Poly1305 tag          |
//!
//! Bytes 0..53 are the wrap's associated data after the file's first bytes and the method byte, so
//! an edit to any of them, the Argon2id cost included, fails the unlock rather than producing a key.
//! The derivation byte is where the lock grows: an unknown value is refused by name, never guessed at.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::cipher::{self, Failed, KEY_LEN, NONCE_LEN, SEALED_LEN};
use crate::envelope::{HEADER_LEN, Refusal};
use crate::error::{CryptoError, FormatError};
use crate::lock::{FileKey, wrap_aad};
use crate::method::Method;
use crate::passphrase::Passphrase;

/// Key derivation: Argon2id at version `0x13`.
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;

// The body's offsets, in order. Every field is fixed-width, so these ARE the grammar.
const AT_KDF: usize = 0;
const AT_MEMORY: usize = AT_KDF + 1;
const AT_PASSES: usize = AT_MEMORY + 4;
const AT_LANES: usize = AT_PASSES + 4;
const AT_SALT: usize = AT_LANES + 4;
const AT_NONCE: usize = AT_SALT + SALT_LEN;
/// Everything before the wrapped file key: the part of the body the wrap authenticates.
const AT_WRAPPED: usize = AT_NONCE + NONCE_LEN;
/// The length of a passphrase lock's body.
pub(crate) const BODY_LEN: usize = AT_WRAPPED + SEALED_LEN;

// The layout is frozen: a file written today must parse forever. Moving a field is a compile error
// here before it is a golden-vector failure in the tests.
const _: () = assert!(AT_WRAPPED == 53 && BODY_LEN == 101);

/// A passphrase lock, parsed: the derivation within bounds, and the wrapped file key.
pub(crate) struct PassphraseLock {
    cost: Cost,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; SEALED_LEN],
}

impl PassphraseLock {
    pub(crate) fn parse(body: &[u8; BODY_LEN]) -> Result<Self, FormatError> {
        match body[AT_KDF] {
            KDF_ARGON2ID => {}
            found => return Err(FormatError::Kdf { found }),
        }
        let cost = Cost::parse(
            u32::from_be_bytes(field(body, AT_MEMORY)),
            u32::from_be_bytes(field(body, AT_PASSES)),
            u32::from_be_bytes(field(body, AT_LANES)),
        )?;
        Ok(Self {
            cost,
            salt: field(body, AT_SALT),
            nonce: field(body, AT_NONCE),
            wrapped: field(body, AT_WRAPPED),
        })
    }

    /// Wrap `file_key` under `passphrase` at the default cost, with a fresh salt and nonce drawn for
    /// this lock alone: locking the same file under the same passphrase twice never reuses either.
    pub(crate) fn wrap(
        passphrase: &Passphrase,
        file_key: &FileKey,
        header: &[u8; HEADER_LEN],
    ) -> Result<Self, CryptoError> {
        let mut salt = [0; SALT_LEN];
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(CryptoError::entropy)?;
        getrandom::fill(&mut nonce).map_err(CryptoError::entropy)?;
        Self::wrap_with(passphrase, file_key, header, Cost::DEFAULT, salt, nonce)
    }

    /// Wrap with every input chosen by the caller. Only [`wrap`](Self::wrap) reaches this outside
    /// the tests; the tests use it to pin the exact bytes this build writes against the golden
    /// vector.
    pub(crate) fn wrap_with(
        passphrase: &Passphrase,
        file_key: &FileKey,
        header: &[u8; HEADER_LEN],
        cost: Cost,
        salt: [u8; SALT_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self, CryptoError> {
        let mut lock = Self {
            cost,
            salt,
            nonce,
            wrapped: [0; SEALED_LEN],
        };
        let key = cost.derive(passphrase, &salt)?;
        lock.wrapped = cipher::seal(&key, &nonce, &lock.aad(header), file_key.bytes())?;
        Ok(lock)
    }

    /// Unwrap the file key with `passphrase`. A wrong passphrase and a damaged lock are the same
    /// refusal, because the cipher cannot tell them apart and a refusal that tried would be a guess an
    /// attacker could probe.
    pub(crate) fn open(
        &self,
        passphrase: &Passphrase,
        header: &[u8; HEADER_LEN],
    ) -> Result<FileKey, Refusal> {
        let key = self
            .cost
            .derive(passphrase, &self.salt)
            .map_err(Refusal::Crypto)?;
        match cipher::open(&key, &self.nonce, &self.aad(header), &self.wrapped) {
            Ok(file_key) => Ok(FileKey::copy_of(&file_key)),
            Err(Failed::Tag) => Err(Refusal::Unlock),
            Err(Failed::Crypto(source)) => Err(Refusal::Crypto(source)),
        }
    }

    /// The body, byte for byte as it sits in the file.
    pub(crate) fn body(&self) -> [u8; BODY_LEN] {
        let mut body = [0; BODY_LEN];
        body[..AT_WRAPPED].copy_from_slice(&self.head());
        body[AT_WRAPPED..].copy_from_slice(&self.wrapped);
        body
    }

    /// The body up to the wrapped file key.
    fn head(&self) -> [u8; AT_WRAPPED] {
        let mut head = [0; AT_WRAPPED];
        head[AT_KDF] = KDF_ARGON2ID;
        head[AT_MEMORY..AT_PASSES].copy_from_slice(&self.cost.memory_kib.to_be_bytes());
        head[AT_PASSES..AT_LANES].copy_from_slice(&self.cost.passes.to_be_bytes());
        head[AT_LANES..AT_SALT].copy_from_slice(&self.cost.lanes.to_be_bytes());
        head[AT_SALT..AT_NONCE].copy_from_slice(&self.salt);
        head[AT_NONCE..].copy_from_slice(&self.nonce);
        head
    }

    fn aad(&self, header: &[u8; HEADER_LEN]) -> Vec<u8> {
        wrap_aad(header, Method::Passphrase, &self.head())
    }
}

/// A fixed-width field of the body. The offsets are constants inside [`BODY_LEN`], asserted above.
fn field<const N: usize>(body: &[u8; BODY_LEN], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&body[at..at + N]);
    out
}

/// The Argon2id cost a lock is wrapped at, bounded on read.
///
/// The ceiling exists because the cost is read from a file before anything is authenticated: a
/// hostile copy could otherwise demand gigabytes and minutes of work from the process that merely
/// tried to open it. It is 256 MiB, four times what a write uses, so a small board unlocking a
/// tampered file still stays out of the out-of-memory killer's reach, where it could take a
/// neighbouring process down with it. This is a policy of this build, not of the format, so a later
/// build can raise it, and a file this one refuses fails with the cost named. The floor exists so
/// that a file written by a careless or foreign writer at a toy cost is refused rather than reported
/// as protected; it is Argon2id's recommended minimum (19 MiB, two passes), pinned here as literals so a dependency changing its own default cannot move which
/// files this build accepts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Cost {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

impl Cost {
    /// What every write uses: 64 MiB, three passes, one lane.
    pub(crate) const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 1,
    };

    /// The cheapest cost a file may carry.
    #[cfg(test)]
    pub(crate) const FLOOR: Self = Self {
        memory_kib: 19 * 1024,
        passes: 2,
        lanes: 1,
    };

    const MEMORY_KIB: (u32, u32) = (19 * 1024, 256 * 1024);
    const PASSES: (u32, u32) = (2, 10);
    const LANES: (u32, u32) = (1, 8);

    pub(crate) fn parse(memory_kib: u32, passes: u32, lanes: u32) -> Result<Self, FormatError> {
        let cost = Self {
            memory_kib,
            passes,
            lanes,
        };
        if !cost.is_bounded() {
            return Err(FormatError::Cost {
                memory_kib,
                passes,
                lanes,
            });
        }
        Ok(cost)
    }

    const fn is_bounded(self) -> bool {
        Self::MEMORY_KIB.0 <= self.memory_kib
            && self.memory_kib <= Self::MEMORY_KIB.1
            && Self::PASSES.0 <= self.passes
            && self.passes <= Self::PASSES.1
            && Self::LANES.0 <= self.lanes
            && self.lanes <= Self::LANES.1
    }

    fn derive(
        self,
        passphrase: &Passphrase,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        let params = Params::new(self.memory_kib, self.passes, self.lanes, Some(KEY_LEN))
            .map_err(CryptoError::kdf)?;
        // The work memory is ours, not argon2's, so it is wiped when it drops: argon2 frees its own
        // unwiped, and the last pass's blocks are enough to rebuild the key without the passphrase.
        // Reserved exactly and fallibly, so a machine short of memory gets an error, not an abort, and
        // filled within that reservation, so it never reallocates and leaves a copy behind.
        let count = params.block_count();
        let mut blocks = Zeroizing::new(Vec::new());
        blocks
            .try_reserve_exact(count)
            .map_err(CryptoError::memory)?;
        blocks.resize(count, Block::default());
        let mut key = Zeroizing::new([0; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(
                passphrase.as_bytes(),
                salt,
                &mut key[..],
                &mut blocks[..],
            )
            .map_err(CryptoError::kdf)?;
        Ok(key)
    }
}

// What this build writes, it must also read.
const _: () = assert!(Cost::DEFAULT.is_bounded());
