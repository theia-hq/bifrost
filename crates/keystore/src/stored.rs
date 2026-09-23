use std::path::PathBuf;

use bifrost_core::NodeId;

use crate::envelope::{Envelope, Refusal};
use crate::error::Error;
use crate::method::Method;
use crate::passphrase::Passphrase;
use crate::secret::Secret;

/// A key file that is present and well-formed: either its key, or the locked form of it.
///
/// Both answer [`node_id`](Self::node_id) and [`method`](Self::method) without a passphrase, so a
/// caller can say which node a file is for, and how it is protected, before deciding whether to ask
/// for anything. For a sealed file that node is the file's claim, not yet a fact; see
/// [`Locked::node_id`].
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

    /// How the file protects its key: the method record, read from the file's own bytes.
    pub fn method(&self) -> Method {
        match self {
            Self::Plain(_) => Method::Plain,
            Self::Locked(locked) => locked.method(),
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

    /// How this file is sealed, from its header.
    pub fn method(&self) -> Method {
        self.envelope.method()
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

    /// Unlock the key with `passphrase`. Success proves the header: the key it returns is the node
    /// [`node_id`](Self::node_id) claims.
    ///
    /// A wrong passphrase and a damaged file both refuse as [`Error::Unlock`]. A failed unlock is a
    /// refusal and nothing more: the file is left as it was, and no key stands in for the one that
    /// did not open.
    pub fn unlock(&self, passphrase: &Passphrase) -> Result<Secret, Error> {
        self.envelope.open(passphrase).map_err(|refusal| {
            let path = self.path.clone();
            match refusal {
                Refusal::Unlock => Error::Unlock { path },
                Refusal::Inconsistent => Error::Inconsistent { path },
                Refusal::Crypto(source) => Error::Crypto { path, source },
            }
        })
    }
}

/// Names the file and the node, never the sealed bytes.
impl core::fmt::Debug for Locked {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Locked")
            .field("path", &self.path)
            .field("node_id", &self.node_id())
            .finish()
    }
}
