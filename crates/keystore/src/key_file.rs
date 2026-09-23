use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use bifrost_core::NodeId;
use zeroize::Zeroizing;

use crate::envelope::{self, Envelope, Parsed};
use crate::error::{CryptoError, Error, FormatError};
use crate::method::Protection;
use crate::secret::Secret;
use crate::stored::{Locked, Stored};

/// The most a key file is read to learn what it is. Far above any version's length, so a later
/// version is still read far enough to be named; far below anything that costs a load to hold, so a
/// huge file or a device at the path is refused on its size without being read.
const READ_CAP: u64 = 4096;

/// A key file at a path: the one place a node's key is loaded from, written to, or rewritten.
///
/// Every write lands whole or not at all. The new bytes are staged in a sibling file created
/// owner-only, synced, read back and unlocked through the same loader every load uses, and only then
/// moved into place, with the directory synced after. A crash at any point leaves either the old file
/// or the new one, never a torn one, and a new form that does not read back as the same key never
/// replaces the old.
///
/// The caller owns the path and its directory: this type creates neither directories nor policy about
/// where a key lives, and it never creates a key on its own.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyFile {
    path: PathBuf,
}

impl From<PathBuf> for KeyFile {
    fn from(path: PathBuf) -> Self {
        Self { path }
    }
}

impl From<&Path> for KeyFile {
    fn from(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
        }
    }
}

impl KeyFile {
    /// The path this key file lives at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the key file: `None` only when nothing is at the path, and otherwise the key or its
    /// locked form.
    ///
    /// A file that is present but not a well-formed key file of this build refuses with the reason,
    /// and absence is reported rather than acted on: whether an absent key should be created is the
    /// caller's decision, and a refusal here must never be read as absence.
    pub fn load(&self) -> Result<Option<Stored>, Error> {
        Ok(self.load_seen()?.map(|(stored, _)| stored))
    }

    /// [`load`](Self::load), and the fingerprint of the file the bytes came from.
    fn load_seen(&self) -> Result<Option<(Stored, Fingerprint)>, Error> {
        let Some(Contents { bytes, seen }) = self.read()? else {
            return Ok(None);
        };
        let stored = match envelope::parse(&bytes) {
            Ok(Parsed::Plain(seed)) => Stored::Plain(Secret::copy_of(seed)),
            Ok(Parsed::Sealed(envelope)) => {
                Stored::Locked(Locked::new(self.path.clone(), envelope))
            }
            Err(source) => return Err(self.format(source)),
        };
        Ok(Some((stored, seen)))
    }

    /// Write `secret` under `protection`, into a path where nothing is.
    ///
    /// Never over anything: a file already at the path, a copy of this same key included, refuses as
    /// [`Error::Occupied`], and the refusal is decided by the filesystem at the instant of publishing,
    /// so two writers racing for one path cannot both win. A symbolic link at the path is something,
    /// even one that points nowhere: a write never lands through a link.
    pub fn write(&self, secret: &Secret, protection: Protection<'_>) -> Result<(), Error> {
        self.sweep();
        let image = self.encode(secret, protection)?;
        self.create(&image, protection, secret.node_id())
    }

    /// Stage `image`, prove it opens under `protection` as `node`, and only then publish it into
    /// absence.
    fn create(&self, image: &[u8], protection: Protection<'_>, node: NodeId) -> Result<(), Error> {
        let staged = self.stage(image)?;
        staged.verify(protection, node)?;
        staged.publish_new()
    }

    /// Install `secret` as this file's key, the way a machine takes on an identity it was given.
    ///
    /// Writes into absence as [`write`](Self::write) does. A file already holding this same key is
    /// left exactly as it is, method included, so adopting twice is a no-op. A file holding a
    /// different key refuses as [`Error::Different`] and is never replaced: that key may be the only
    /// copy there is. A file that cannot be read refuses for its own reason rather than counting as
    /// absent.
    ///
    /// "Holding this same key" is proven, never taken from a sealed file's header, which only CLAIMS
    /// a node until it unlocks (see [`Locked::node_id`]). A sealed file claiming this key is unlocked
    /// with the passphrase `protection` carries, and a failed unlock refuses as it would anywhere.
    /// Offered [`Protection::Plain`], there is no passphrase to prove it with, so it refuses as
    /// [`Error::Unconfirmed`] rather than succeed on the claim.
    pub fn adopt(&self, secret: &Secret, protection: Protection<'_>) -> Result<(), Error> {
        let incoming = secret.node_id();
        match self.load()? {
            None => self.write(secret, protection),
            Some(stored) if stored.node_id() != incoming => Err(Error::Different {
                path: self.path.clone(),
                existing: stored.node_id(),
                incoming,
            }),
            // A plain file's node is computed from the key it holds, so it is a fact, not a claim.
            Some(Stored::Plain(_)) => Ok(()),
            // The unlock proves the claim: it succeeds only when the sealed key IS the header's node.
            Some(Stored::Locked(locked)) => match protection {
                Protection::Passphrase(passphrase) => locked.unlock(passphrase).map(drop),
                Protection::Plain => Err(Error::Unconfirmed {
                    path: self.path.clone(),
                    claimed: incoming,
                }),
            },
        }
    }

    /// Rewrite the key file from one protection to another: plain to passphrase, passphrase to plain,
    /// or one passphrase to a new one. The key, and so the node, never changes.
    ///
    /// In this order, and nothing reaches the next step until the last one held:
    ///
    /// 1. **unlock** the file as it stands with `from`, which must name the method the file records;
    /// 2. **re-wrap** the key under `to`, a passphrase seal drawing a fresh salt and nonce;
    /// 3. **test-unlock** the new form, staged beside the file, through the same loader every load
    ///    uses, and require the same node back;
    /// 4. **atomically rename** it over the file, then sync the directory.
    ///
    /// Until step 4 the original is untouched, so a wrong passphrase, a crash, or a new form that does
    /// not read back leaves the file readable exactly as before.
    ///
    /// Just before the rename, the file at the path must still be the one step 1 read. If something
    /// replaced or changed it meanwhile (a restore, an adopt, another migration), the migration
    /// refuses as [`Error::Changed`] rather than write the old key over the new one, which may be the
    /// only copy of it. What remains is the instant between that check and the rename; closing it
    /// entirely takes a lock the caller holds across every change to its key files.
    ///
    /// Sealing a key that was stored plain protects the file from here on. It does not reach copies
    /// made while it was plain (backups, snapshots, the disk blocks the old file occupied), so a key
    /// that may have leaked is replaced with a new key, not sealed.
    ///
    /// A path that is a symbolic link is resolved first, and the file it names is the one rewritten,
    /// staged beside it: a key file kept elsewhere and linked into place (a dotfile manager's layout)
    /// is loaded through the link, so it must be protected through it too. Renaming over the link
    /// itself would leave the link's target, the file actually kept, holding the old form, while the
    /// path reported the new one. Refusals after that point name the file the link resolved to.
    pub fn migrate(&self, from: Protection<'_>, to: Protection<'_>) -> Result<(), Error> {
        let real = self.resolved()?;
        real.sweep();
        let (secret, seen) = real.unlock(from)?;
        let image = real.encode(&secret, to)?;
        real.replace(&image, to, secret.node_id(), &seen)
    }

    /// This key file at the path it finally names, every symbolic link on the way resolved.
    fn resolved(&self) -> Result<Self, Error> {
        match fs::canonicalize(&self.path) {
            Ok(path) => Ok(Self { path }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(Error::Absent {
                path: self.path.clone(),
            }),
            Err(source) => Err(self.io(source)),
        }
    }

    /// Step 1 of a migration: the key as the file stands, opened with what the caller says it is, and
    /// the fingerprint of the file it came from.
    fn unlock(&self, from: Protection<'_>) -> Result<(Secret, Fingerprint), Error> {
        let Some((stored, seen)) = self.load_seen()? else {
            return Err(Error::Absent {
                path: self.path.clone(),
            });
        };
        let secret = match (stored, from) {
            (Stored::Plain(secret), Protection::Plain) => secret,
            (Stored::Locked(locked), Protection::Passphrase(passphrase)) => {
                locked.unlock(passphrase)?
            }
            (stored, from) => {
                return Err(Error::WrongMethod {
                    path: self.path.clone(),
                    stored: stored.method(),
                    given: from.method(),
                });
            }
        };
        Ok((secret, seen))
    }

    /// Steps 3 and 4 of a migration: stage `image`, prove it opens under `to` as `node`, confirm the
    /// file is still the one `seen` describes, and only then rename it over the file.
    fn replace(
        &self,
        image: &[u8],
        to: Protection<'_>,
        node: NodeId,
        seen: &Fingerprint,
    ) -> Result<(), Error> {
        let staged = self.stage(image)?;
        staged.verify(to, node)?;
        // Checked last, after the slow unlock of the stage, so the window it leaves is as short as it
        // can be without a lock.
        match fs::metadata(&self.path) {
            Ok(now) if Fingerprint::of(&now) == *seen => {}
            Ok(_) => return Err(self.changed()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(self.changed()),
            Err(source) => return Err(self.io(source)),
        }
        staged.publish_over()
    }

    /// The bytes a file holding `secret` under `protection` consists of.
    fn encode(
        &self,
        secret: &Secret,
        protection: Protection<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        match protection {
            Protection::Plain => Ok(secret.with_bytes(|seed| Zeroizing::new(seed.to_vec()))),
            Protection::Passphrase(passphrase) => Envelope::seal(secret, passphrase)
                .map(|envelope| Zeroizing::new(envelope.image().to_vec()))
                .map_err(|source| Error::Crypto {
                    path: self.path.clone(),
                    source,
                }),
        }
    }

    /// Read the file's bytes and fingerprint, or `None` when nothing is at the path.
    fn read(&self) -> Result<Option<Contents>, Error> {
        let mut file = match open_for_reading(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(self.io(source)),
        };
        // Every check that decides whether to trust the bytes reads the OPEN handle, and the bytes
        // come from that same handle, so nothing swapped in at the path afterwards can slip past
        // these.
        let metadata = file.metadata().map_err(|source| self.io(source))?;
        if !metadata.is_file() {
            return Err(self.not_a_file());
        }
        self.guard_access(&metadata, effective_uid())?;
        let len = metadata.len();
        if len > READ_CAP {
            return Err(self.format(FormatError::Size { found: len }));
        }
        // Sized once from the handle and filled in place: the buffer never grows, so no reallocation
        // leaves an unwiped copy of the key behind in freed memory.
        // Lossless: `len` is at most READ_CAP.
        let mut bytes = Zeroizing::new(vec![0; len as usize]);
        file.read_exact(&mut bytes)
            .map_err(|source| self.io(source))?;
        Ok(Some(Contents {
            bytes,
            seen: Fingerprint::of(&metadata),
        }))
    }

    /// Refuse a file that anyone but its owner can read, or whose owner is neither `euid` (this
    /// process's effective user) nor root. Read from the open handle; unix only, because no other
    /// platform has an owner and mode to read, and a check that pretended would be false assurance.
    ///
    /// The owner matters as much as the mode: a node running as root would otherwise load an
    /// owner-only key that any user able to place a file at the path had put there. Root is allowed
    /// as an owner because a key installed by an administrator for a service is root's to give.
    fn guard_access(&self, metadata: &fs::Metadata, euid: u32) -> Result<(), Error> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let owner = metadata.uid();
            if owner != euid && owner != 0 {
                return Err(Error::Owner {
                    path: self.path.clone(),
                    owner,
                });
            }
            let mode = metadata.mode();
            if mode & 0o077 != 0 {
                return Err(Error::Permissive {
                    path: self.path.clone(),
                    mode: mode & 0o7777,
                });
            }
        }
        #[cfg(not(unix))]
        let _ = (metadata, euid);
        Ok(())
    }

    /// Remove staging files a crashed write or migration left beside the key file.
    ///
    /// A stage is removed on every path a running process takes, but not when the process is killed
    /// or the power fails, and a stage left by an earlier plain write still holds that plain seed after
    /// the key file is sealed. Only a name of the exact staging shape, a regular file this user owns,
    /// is removed. Best effort: a sibling that cannot be listed or removed does not stop the write.
    ///
    /// A write racing this one on the same path can lose its stage here. It then fails, leaving the
    /// key file as it was: the same outcome as losing the race to publish.
    fn sweep(&self) {
        let (Some(name), Some(dir)) = (self.path.file_name(), self.path.parent()) else {
            return;
        };
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let euid = effective_uid();
        for entry in entries.flatten() {
            let sibling = entry.file_name();
            if !is_stage_of(name, &sibling) {
                continue;
            }
            // `symlink_metadata`: a link under a staging name is judged as itself, and a stage is only
            // ever a regular file, so a link is not one and is left where it is.
            let Ok(metadata) = entry.path().symlink_metadata() else {
                continue;
            };
            if metadata.is_file() && owned_by(&metadata, euid) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    /// Write `image` to a fresh owner-only sibling and sync it.
    fn stage(&self, image: &[u8]) -> Result<Staged<'_>, Error> {
        let temp = self.temp_path()?;
        let mut file = create_private(&temp).map_err(|source| self.io(source))?;
        // Armed only once the sibling exists and is ours: `create_new` refused any name already
        // taken, so the cleanup below can never remove a file this call did not create.
        let staged = Staged {
            target: self,
            temp,
            published: false,
        };
        file.write_all(image)
            .and_then(|()| file.sync_all())
            .map_err(|source| self.io(source))?;
        Ok(staged)
    }

    /// A sibling of the key file, unique to this process and this call, in the same directory so the
    /// rename that publishes it is atomic.
    fn temp_path(&self) -> Result<PathBuf, Error> {
        let Some(name) = self.path.file_name() else {
            return Err(self.not_a_file());
        };
        let nonce = getrandom::u64().map_err(|source| Error::Crypto {
            path: self.path.clone(),
            source: CryptoError::entropy(source),
        })?;
        let mut temp = name.to_owned();
        temp.push(format!(".tmp.{}.{nonce:016x}", std::process::id()));
        Ok(self.path.with_file_name(temp))
    }

    /// Sync the directory, so the rename that published the file survives a power loss. Runs only
    /// after the publish, so its failure is [`Error::Unsynced`]: the key is in place already.
    fn sync_dir(&self) -> Result<(), Error> {
        #[cfg(unix)]
        {
            let dir = match self.path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            File::open(dir)
                .and_then(|dir| dir.sync_all())
                .map_err(|source| Error::Unsynced {
                    path: self.path.clone(),
                    source,
                })?;
        }
        Ok(())
    }

    fn io(&self, source: io::Error) -> Error {
        Error::Io {
            path: self.path.clone(),
            source,
        }
    }

    fn format(&self, source: FormatError) -> Error {
        Error::Format {
            path: self.path.clone(),
            source,
        }
    }

    fn changed(&self) -> Error {
        Error::Changed {
            path: self.path.clone(),
        }
    }

    fn not_a_file(&self) -> Error {
        Error::NotAFile {
            path: self.path.clone(),
        }
    }
}

/// A new key file image, written and synced beside its target, not yet in place. Dropped
/// unpublished, it removes itself; the target was never touched.
struct Staged<'a> {
    target: &'a KeyFile,
    temp: PathBuf,
    // Set once the staging name is gone by the publish itself, so `drop` has nothing to remove.
    published: bool,
}

impl Staged<'_> {
    /// Read the staged file back through the loader and unlock it with `protection`: it must hold
    /// `node`. What is about to become the key file is proven to open before it does.
    fn verify(&self, protection: Protection<'_>, node: NodeId) -> Result<(), Error> {
        let opened = match (KeyFile::from(self.temp.as_path()).load(), protection) {
            (Ok(Some(Stored::Plain(secret))), Protection::Plain) => Some(secret),
            (Ok(Some(Stored::Locked(locked))), Protection::Passphrase(passphrase)) => {
                locked.unlock(passphrase).ok()
            }
            _ => None,
        };
        match opened {
            Some(secret) if secret.node_id() == node => Ok(()),
            _ => Err(Error::Unverified {
                path: self.target.path.clone(),
            }),
        }
    }

    /// Publish into absence: a hard link fails if anything is at the target, so the no-clobber
    /// check and the publish are one atomic step, then the staging name is removed.
    fn publish_new(mut self) -> Result<(), Error> {
        let target = self.target;
        match fs::hard_link(&self.temp, &target.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(Error::Occupied {
                    path: target.path.clone(),
                });
            }
            // No fallback that could land over a file: a filesystem without hard links cannot hold
            // a key this crate writes.
            Err(source) if lacks_hard_links(&source) => {
                return Err(Error::NoHardLinks {
                    path: target.path.clone(),
                    source,
                });
            }
            Err(source) => return Err(target.io(source)),
        }
        // The key is in place under its own name now. The staging name goes BEFORE the directory is
        // synced, so the state that sync makes durable has one name for the key, and a power loss
        // cannot bring back a second link to it that no later write knows about.
        let _ = fs::remove_file(&self.temp);
        self.published = true;
        target.sync_dir()
    }

    /// Publish over the existing file: one rename, atomic within the directory.
    fn publish_over(mut self) -> Result<(), Error> {
        let target = self.target;
        fs::rename(&self.temp, &target.path).map_err(|source| target.io(source))?;
        // Renamed away: the staging name is gone, and nothing is left for `drop` to remove.
        self.published = true;
        target.sync_dir()
    }
}

impl Drop for Staged<'_> {
    fn drop(&mut self) {
        if !self.published {
            // Best effort: the target is intact either way, and a leftover sibling is owner-only.
            let _ = fs::remove_file(&self.temp);
        }
    }
}

/// A key file's bytes, and which file they came from.
struct Contents {
    bytes: Zeroizing<Vec<u8>>,
    seen: Fingerprint,
}

/// Which file a load read: enough to tell, just before a migration renames over it, whether the path
/// still names that file unchanged. The inode and device say it is the same file; the size and the
/// change time say nothing was written to it, and the change time is one a writer cannot set back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fingerprint {
    #[cfg(unix)]
    file: (u64, u64),
    len: u64,
    #[cfg(unix)]
    changed: (i64, i64),
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl Fingerprint {
    fn of(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            Self {
                file: (metadata.dev(), metadata.ino()),
                len: metadata.len(),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }
}

/// Whether `sibling` has the exact shape of a staging name for the key file `name`:
/// `<name>.tmp.<pid>.<16 hex digits>`, as [`KeyFile::temp_path`] builds it.
fn is_stage_of(name: &OsStr, sibling: &OsStr) -> bool {
    let (Some(name), Some(sibling)) = (name.to_str(), sibling.to_str()) else {
        return false;
    };
    let Some(rest) = sibling
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix(".tmp."))
    else {
        return false;
    };
    let Some((pid, nonce)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && nonce.len() == 16
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `euid` owns the file. Where there is no owner to read, nothing is removed on its say-so.
fn owned_by(metadata: &fs::Metadata, euid: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        metadata.uid() == euid
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, euid);
        false
    }
}

/// This process's effective user id. Where there is none, `0`, which no check here compares against.
fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        crate::uid::effective()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Open `path` to read it without ever blocking on what it names.
///
/// Opening a pipe for reading blocks until a writer appears, and a check made before the open is
/// always a step behind a path that changes, so the open itself must not wait: non-blocking, and never
/// taking a terminal as this process's controlling one. For a regular file neither flag changes a
/// thing, and anything else is refused from the handle once it is open.
fn open_for_reading(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    options.open(path)
}

/// Whether a hard link failed because the filesystem has none: `ENOTSUP` or `EOPNOTSUPP` where the
/// platform says so (FAT and exFAT on macOS), `EPERM` where it does not (FAT on Linux, where a denied
/// permission is `EACCES` instead). Matched by number, because the standard library files `ENOTSUP`
/// under no specific kind.
fn lacks_hard_links(error: &io::Error) -> bool {
    #[cfg(unix)]
    if let Some(errno) = error.raw_os_error() {
        return [libc::ENOTSUP, libc::EOPNOTSUPP, libc::EPERM].contains(&errno);
    }
    error.kind() == io::ErrorKind::Unsupported
}

/// Create the staging file new and owner-only: `create_new` refuses a name already taken, and the
/// mode is set AT creation (`0600` on unix), so the key is never readable by group or other, not
/// even for the instant before a chmod could tighten it.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
#[path = "key_file_tests.rs"]
mod key_file_tests;
