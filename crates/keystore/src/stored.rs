use std::path::PathBuf;

use bifrost_core::NodeId;

use crate::envelope::{Envelope, Opened, Refusal};
use crate::error::Error;
use crate::method::{Method, Unlock};
use crate::secret::Secret;

/// A key file that is present and well-formed: either its key, or the locked form of it.
///
/// Both answer [`node_id`](Self::node_id) without unlocking, and a locked file names its locks
/// ([`Locked::methods`]), so a caller can say which node a file is for, and how it opens, before
/// deciding whether to ask for anything. For a sealed file that node is the file's claim, not yet a
/// fact; see [`Locked::node_id`].
#[derive(Debug)]
pub enum Stored {
    /// A plain file: the key, ready to use.
    Plain(Secret),
    /// A sealed file: the key is inside, and [`Locked::unlock`] is the only way to it.
    Locked(Locked),
}

impl Stored {
    /// The node the file is for: for a plain file, computed from the key it holds; for a sealed
    /// file, what its header claims, proven only by [`Locked::unlock`].
    pub fn node_id(&self) -> NodeId {
        match self {
            Self::Plain(secret) => secret.node_id(),
            Self::Locked(locked) => locked.node_id(),
        }
    }
}

/// A sealed key file, parsed and bounded but not yet unlocked.
pub struct Locked {
    path: PathBuf,
    // Boxed so a `Stored` is two pointers wide either way, rather than the size of a sealed file.
    envelope: Box<Envelope>,
}

impl Locked {
    pub(crate) fn new(path: PathBuf, envelope: Envelope) -> Self {
        Self {
            path,
            envelope: Box::new(envelope),
        }
    }

    /// The methods of this file's locks, from its header, in file order. At least one, and never one
    /// method twice. Any one of them opens the file.
    pub fn methods(&self) -> impl Iterator<Item = Method> + '_ {
        self.envelope.methods()
    }

    /// The node this file CLAIMS to seal, read from its header without unlocking.
    ///
    /// A claim, not a fact, until [`unlock`](Self::unlock) succeeds. The header is authenticated as
    /// part of the unlock, and nothing checks it before: anyone who can write the file can make it
    /// claim any node, and the file then fails to unlock rather than open as that node. Use this to
    /// show which node a file is for or to decide what to ask for; never to conclude that the file
    /// holds a key. [`KeyFile::adopt`](crate::KeyFile::adopt) proves a claim by unlocking it.
    pub fn node_id(&self) -> NodeId {
        self.envelope.node_id()
    }

    /// Unlock the key through the lock `with` opens. Success proves the header: the key it returns
    /// is the node [`node_id`](Self::node_id) claims.
    ///
    /// A file with no lock of `with`'s method refuses as [`Error::NoLock`]. A wrong passphrase and a
    /// damaged file both refuse as [`Error::Unlock`]. A failed unlock is a refusal and nothing more:
    /// the file is left as it was, and no key stands in for the one that did not open.
    pub fn unlock(&self, with: Unlock<'_>) -> Result<Secret, Error> {
        self.open(with).map(|opened| opened.secret)
    }

    /// [`unlock`](Self::unlock), keeping the file key a lock change re-wraps.
    pub(crate) fn open(&self, with: Unlock<'_>) -> Result<Opened, Error> {
        self.envelope
            .unlock(with)
            .map_err(|refusal| self.refused(refusal))
    }

    pub(crate) fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// A refusal, with this file's path attached.
    pub(crate) fn refused(&self, refusal: Refusal) -> Error {
        let path = self.path.clone();
        match refusal {
            Refusal::Unlock => Error::Unlock { path },
            Refusal::Inconsistent => Error::Inconsistent { path },
            Refusal::NoLock(method) => Error::NoLock { path, method },
            Refusal::Crypto(source) => Error::Crypto { path, source },
        }
    }
}

/// Names the file, the node, and its locks, never the sealed bytes.
impl core::fmt::Debug for Locked {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Locked")
            .field("path", &self.path)
            .field("node_id", &self.node_id())
            .field("methods", &self.methods().collect::<Vec<_>>())
            .finish()
    }
}
