//! The key file format: the one parser, and the writer beside it.
//!
//! A key file is one of two shapes, told apart by its first eight bytes:
//!
//! - **plain**: exactly the 32-byte ed25519 seed, nothing else;
//! - **sealed**: [`SIGNATURE`], then a version byte that governs everything after it. Version 1 is
//!   144 bytes, every field fixed-width, integers big-endian:
//!
//! | offset | len | field                                                           |
//! | ------ | --- | --------------------------------------------------------------- |
//! | 0      | 8   | signature `THEIAKEY`                                            |
//! | 8      | 1   | format version, `1`                                             |
//! | 9      | 1   | file kind, `1` = a device key, `2` = a root key                 |
//! | 10     | 1   | protection method, `1` = passphrase                             |
//! | 11     | 1   | key derivation function, `1` = Argon2id, version `0x13`         |
//! | 12     | 4   | Argon2id memory, KiB                                            |
//! | 16     | 4   | Argon2id passes                                                 |
//! | 20     | 4   | Argon2id lanes                                                  |
//! | 24     | 16  | salt                                                            |
//! | 40     | 24  | XChaCha20-Poly1305 nonce                                        |
//! | 64     | 32  | the seed's ed25519 public key, so a locked file names its node  |
//! | 96     | 32  | the seed, encrypted                                             |
//! | 128    | 16  | Poly1305 tag                                                    |
//!
//! Bytes 0..96 are the header, and the header is the cipher's associated data exactly as it sits in
//! the file: every field above the ciphertext is authenticated, so an edit to any of them, the
//! Argon2id cost included, fails the unlock rather than producing a key. The version, kind, method,
//! and derivation bytes are where the format grows: a new value is a new meaning, and an unknown value
//! is refused by name, never guessed at.
//!
//! The kind says what the key is FOR, and a file is only ever read as the kind its reader expects: a
//! sealed device key presented where a root key belongs is refused by its kind, and so is the reverse.
//! Both kinds carry an ed25519 seed under the same layout; only the byte, which the seal authenticates,
//! tells them apart. A plain file has no header and so no kind: it is the seed and nothing else.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use bifrost_core::{CryptoKind, NodeId};
use chacha20poly1305::aead::{AeadInPlace as _, KeyInit as _};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, FormatError};
use crate::kind::Kind;
use crate::method::Method;
use crate::passphrase::Passphrase;
use crate::secret::{SEED_LEN, Secret};

/// Every sealed key file opens with these bytes, at every version, forever.
///
/// Eight bytes rather than a four-byte wire magic, because a sealed file shares its namespace with a
/// plain one, and a plain file is 32 uniformly random bytes: at eight, the chance that a seed someone
/// already holds happens to open with the signature (and would then be refused as a damaged sealed
/// file) is one in 2^64, where four would make it one in 2^32. The version lives in its own byte for
/// the same reason: the signature never changes, so it can never collide with itself.
pub(crate) const SIGNATURE: [u8; 8] = *b"THEIAKEY";

/// The one format version this build reads and writes.
const VERSION: u8 = 1;
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

/// Protection method: sealed under a passphrase.
const METHOD_PASSPHRASE: u8 = 1;
/// Key derivation: Argon2id at version `0x13`.
const KDF_ARGON2ID: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// The derived key is an XChaCha20-Poly1305 key.
const KEY_LEN: usize = 32;

// Version 1's offsets, in file order. Every field is fixed-width, so these ARE the grammar.
const AT_VERSION: usize = SIGNATURE.len();
const AT_KIND: usize = AT_VERSION + 1;
const AT_METHOD: usize = AT_KIND + 1;
const AT_KDF: usize = AT_METHOD + 1;
const AT_MEMORY: usize = AT_KDF + 1;
const AT_PASSES: usize = AT_MEMORY + 4;
const AT_LANES: usize = AT_PASSES + 4;
const AT_SALT: usize = AT_LANES + 4;
const AT_NONCE: usize = AT_SALT + SALT_LEN;
pub(crate) const AT_PUBLIC: usize = AT_NONCE + NONCE_LEN;
/// The header is everything before the ciphertext, and it is exactly the associated data.
pub(crate) const HEADER_LEN: usize = AT_PUBLIC + NodeId::KEY_LEN;
const AT_TAG: usize = HEADER_LEN + SEED_LEN;
/// The length of a version 1 sealed file.
pub(crate) const SEALED_LEN: usize = AT_TAG + TAG_LEN;

// The layout is frozen: a file written today must parse forever. Moving a field is a compile error
// here before it is a golden-vector failure in the tests.
const _: () = assert!(HEADER_LEN == 96 && SEALED_LEN == 144);

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

/// A sealed key file, parsed: every structural byte checked, the cost within bounds, and the bytes
/// kept exactly as read so the header authenticates as it sits in the file.
pub(crate) struct Envelope {
    image: [u8; SEALED_LEN],
    method: Method,
    cost: Cost,
    node_id: NodeId,
}

impl Envelope {
    fn parse(bytes: &[u8], expected: Kind) -> Result<Self, FormatError> {
        // The version governs the length, so it is read before the length is judged: a file from a
        // later version is named as that, not as a damaged version 1 file.
        let Some(&version) = bytes.get(AT_VERSION) else {
            return Err(FormatError::SealedSize {
                found: bytes.len() as u64,
            });
        };
        if version != VERSION {
            return Err(FormatError::Version { found: version });
        }
        let image = <[u8; SEALED_LEN]>::try_from(bytes).map_err(|_| FormatError::SealedSize {
            found: bytes.len() as u64,
        })?;
        match Kind::of_byte(image[AT_KIND]) {
            Some(found) if found == expected => {}
            Some(found) => return Err(FormatError::WrongKind { expected, found }),
            None => {
                return Err(FormatError::Kind {
                    found: image[AT_KIND],
                });
            }
        }
        let method = match image[AT_METHOD] {
            METHOD_PASSPHRASE => Method::Passphrase,
            found => return Err(FormatError::Method { found }),
        };
        match image[AT_KDF] {
            KDF_ARGON2ID => {}
            found => return Err(FormatError::Kdf { found }),
        }
        let cost = Cost::parse(
            u32::from_be_bytes(field(&image, AT_MEMORY)),
            u32::from_be_bytes(field(&image, AT_PASSES)),
            u32::from_be_bytes(field(&image, AT_LANES)),
        )?;
        let node_id = NodeId::new(CryptoKind::Ed25519, field(&image, AT_PUBLIC));
        Ok(Self {
            image,
            method,
            cost,
            node_id,
        })
    }

    /// Seal `secret` as a key of `kind` under `passphrase` at the default cost, with a fresh salt and
    /// nonce drawn for this seal alone: re-sealing the same seed under the same passphrase never reuses
    /// either.
    pub(crate) fn seal(
        secret: &Secret,
        kind: Kind,
        passphrase: &Passphrase,
    ) -> Result<Self, CryptoError> {
        let mut salt = [0; SALT_LEN];
        let mut nonce = [0; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(CryptoError::entropy)?;
        getrandom::fill(&mut nonce).map_err(CryptoError::entropy)?;
        let public = secret.node_id();
        Self::seal_with(
            secret,
            kind,
            public,
            passphrase,
            Cost::DEFAULT,
            &salt,
            &nonce,
        )
    }

    /// Seal with every input chosen by the caller. Only [`seal`](Self::seal) reaches this outside the
    /// tests; the tests use it to pin the exact bytes this build writes against the golden vector, and
    /// to build a file whose header names a key other than the one it seals.
    pub(crate) fn seal_with(
        secret: &Secret,
        kind: Kind,
        public: NodeId,
        passphrase: &Passphrase,
        cost: Cost,
        salt: &[u8; SALT_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, CryptoError> {
        let mut image = [0; SEALED_LEN];
        image[..AT_VERSION].copy_from_slice(&SIGNATURE);
        image[AT_VERSION] = VERSION;
        image[AT_KIND] = kind.byte();
        image[AT_METHOD] = METHOD_PASSPHRASE;
        image[AT_KDF] = KDF_ARGON2ID;
        image[AT_MEMORY..AT_PASSES].copy_from_slice(&cost.memory_kib.to_be_bytes());
        image[AT_PASSES..AT_LANES].copy_from_slice(&cost.passes.to_be_bytes());
        image[AT_LANES..AT_SALT].copy_from_slice(&cost.lanes.to_be_bytes());
        image[AT_SALT..AT_NONCE].copy_from_slice(salt);
        image[AT_NONCE..AT_PUBLIC].copy_from_slice(nonce);
        image[AT_PUBLIC..HEADER_LEN].copy_from_slice(public.key());

        let key = cost.derive(passphrase, salt)?;
        // Encrypt in a wiping buffer, not in `image`: if sealing fails partway, the plaintext seed
        // must not be left in a plain array on its way out of scope.
        let mut sealed = Zeroizing::new([0; SEED_LEN]);
        secret.with_bytes(|seed| sealed.copy_from_slice(seed));
        // Built from arrays and the checked slice constructor, never `from_slice`, which newer
        // releases of the array crate deprecate and a consumer's lock may resolve to.
        let tag = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| CryptoError::cipher())?
            .encrypt_in_place_detached(&XNonce::from(*nonce), &image[..HEADER_LEN], &mut sealed[..])
            .map_err(|_| CryptoError::cipher())?;
        image[HEADER_LEN..AT_TAG].copy_from_slice(&sealed[..]);
        image[AT_TAG..].copy_from_slice(&tag);
        Ok(Self {
            image,
            method: Method::Passphrase,
            cost,
            node_id: public,
        })
    }

    /// Unlock with `passphrase`. A wrong passphrase and a damaged file are the same refusal, because
    /// the cipher cannot tell them apart and a refusal that tried would be a guess an attacker could
    /// probe.
    pub(crate) fn open(&self, passphrase: &Passphrase) -> Result<Secret, Refusal> {
        let key = self
            .cost
            .derive(passphrase, &self.image[AT_SALT..AT_NONCE])
            .map_err(Refusal::Crypto)?;
        let mut seed = Zeroizing::new(field::<SEED_LEN>(&self.image, HEADER_LEN));
        XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| Refusal::Crypto(CryptoError::cipher()))?
            .decrypt_in_place_detached(
                &XNonce::from(field::<NONCE_LEN>(&self.image, AT_NONCE)),
                &self.image[..HEADER_LEN],
                &mut seed[..],
                &Tag::from(field::<TAG_LEN>(&self.image, AT_TAG)),
            )
            .map_err(|_| Refusal::Unlock)?;
        let secret = Secret::copy_of(&seed);
        // The header's public key is authenticated, but only a writer holding the passphrase could
        // have put a mismatched one there. A locked file must never name a node it would not unlock
        // into, so the mismatch is refused rather than trusted either way.
        if secret.node_id() != self.node_id {
            return Err(Refusal::Inconsistent);
        }
        Ok(secret)
    }

    /// The method this file records, read from the header.
    pub(crate) const fn method(&self) -> Method {
        self.method
    }

    /// The node this file seals, read from the header without unlocking.
    pub(crate) const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The file's bytes, exactly as parsed or sealed.
    pub(crate) const fn image(&self) -> &[u8; SEALED_LEN] {
        &self.image
    }
}

/// Why a parsed envelope did not unlock. The key file attaches its path to each.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// Wrong passphrase, or the file was damaged: deliberately one case.
    Unlock,
    /// The seal opened, but the header names a different key.
    Inconsistent,
    /// Argon2id could not run.
    Crypto(CryptoError),
}

/// A fixed-width field of the image. The offsets are constants inside [`SEALED_LEN`], asserted above.
fn field<const N: usize>(image: &[u8; SEALED_LEN], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&image[at..at + N]);
    out
}

/// The Argon2id cost a file is sealed at, bounded on read.
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

    fn parse(memory_kib: u32, passes: u32, lanes: u32) -> Result<Self, FormatError> {
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

#[cfg(test)]
#[path = "envelope_tests.rs"]
mod envelope_tests;
