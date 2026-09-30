use core::fmt;

use crate::passphrase::Passphrase;

/// How one lock on a sealed key file opens: the method record, read from the file's own bytes.
///
/// A sealed file holds a list of locks, at most one per method, and any one of them opens it. A
/// plain file holds none, so plain is not a method: it is the absence of every lock.
///
/// Deliberately exhaustive: a method added later must be a compile error at every `match` that
/// decides something by method. Only built methods are variants; a name reserved for the future is
/// not registered here, in the file format, or anywhere a value could carry it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    /// A passphrase: Argon2id derives a key from it, and XChaCha20-Poly1305 wraps the file key under
    /// that.
    Passphrase,
}

/// The method's name, the one word a person sees for it.
impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Passphrase => "passphrase",
        })
    }
}

/// What a caller holds to open one lock: the input to [`Locked::unlock`](crate::Locked::unlock), and
/// the proof a lock change starts from. Each variant carries what its method needs, so a passphrase
/// unlock without its passphrase cannot be expressed.
#[derive(Clone, Copy, Debug)]
pub enum Unlock<'a> {
    /// Open the passphrase lock with this passphrase.
    Passphrase(&'a Passphrase),
}

impl Unlock<'_> {
    /// The method of the lock this opens.
    pub const fn method(&self) -> Method {
        match self {
            Self::Passphrase(_) => Method::Passphrase,
        }
    }
}

/// A lock to put on a key file: what [`KeyFile::add_lock`](crate::KeyFile::add_lock) wraps the file
/// key under.
#[derive(Clone, Copy, Debug)]
pub enum NewLock<'a> {
    /// A passphrase lock under this passphrase.
    Passphrase(&'a Passphrase),
}

impl<'a> NewLock<'a> {
    /// The method of the lock this makes.
    pub const fn method(&self) -> Method {
        match self {
            Self::Passphrase(_) => Method::Passphrase,
        }
    }

    /// What opens the lock this makes, so a rewrite is proven through the lock it just added.
    pub(crate) const fn opener(self) -> Unlock<'a> {
        match self {
            Self::Passphrase(passphrase) => Unlock::Passphrase(passphrase),
        }
    }
}

/// How a new key file is written: plain, or sealed with one lock. The input to
/// [`KeyFile::write`](crate::KeyFile::write) and [`KeyFile::adopt`](crate::KeyFile::adopt), where the
/// same passphrase also proves a sealed file already at the path.
#[derive(Clone, Copy, Debug)]
pub enum Protection<'a> {
    /// Store the raw seed.
    Plain,
    /// Seal the seed under one passphrase lock, or unlock it with this passphrase.
    Passphrase(&'a Passphrase),
}
