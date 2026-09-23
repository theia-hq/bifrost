use core::fmt;

use crate::passphrase::Passphrase;

/// How a key file protects its seed: the method record, read from the file's own bytes.
///
/// Deliberately exhaustive: a method added later must be a compile error at every `match` that
/// decides something by method. Only built methods are variants; a name reserved for the future is
/// not registered here, in the file format, or anywhere a value could carry it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    /// The raw 32-byte seed, protected by the file's owner-only mode and nothing else.
    Plain,
    /// The seed sealed under a passphrase: Argon2id derives the key, XChaCha20-Poly1305 seals it.
    Passphrase,
}

/// The method's name, the one word a person sees for it.
impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Plain => "plain",
            Self::Passphrase => "passphrase",
        })
    }
}

/// A method together with what it needs to seal or unlock: the input to a write, and both ends of a
/// migration. A [`Method`] says what a file IS; a `Protection` is what a caller HOLDS to make or open
/// one, so a passphrase method without its passphrase cannot be expressed.
#[derive(Clone, Copy, Debug)]
pub enum Protection<'a> {
    /// Store the raw seed.
    Plain,
    /// Seal the seed under this passphrase, or unlock it with this passphrase.
    Passphrase(&'a Passphrase),
}

impl Protection<'_> {
    /// The method this protection produces or opens.
    pub const fn method(&self) -> Method {
        match self {
            Self::Plain => Method::Plain,
            Self::Passphrase(_) => Method::Passphrase,
        }
    }
}
