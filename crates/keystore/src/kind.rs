use core::fmt;

/// What a key file's key is for: a device's own key, or a root key.
///
/// A property of the SLOT a file is read from, chosen when the [`KeyFile`](crate::KeyFile) is named
/// ([`KeyFile::device`](crate::KeyFile::device), [`KeyFile::root`](crate::KeyFile::root)), and recorded
/// in every sealed file it writes. A sealed file of the other kind is refused where this kind is
/// expected, so a device key can never stand in for a root key, or a root key for a device key.
///
/// Deliberately exhaustive, like [`Method`](crate::Method): a kind added later must be a compile error
/// at every `match` that decides something by kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A device's own key: plain or sealed, as its owner chooses.
    Device,
    /// A root key: always sealed when written.
    Root,
}

/// The kind's name, the words a person sees for it.
impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Device => "device key",
            Self::Root => "root key",
        })
    }
}
