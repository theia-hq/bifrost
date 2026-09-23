use core::fmt;

use icu_normalizer::ComposingNormalizerBorrowed;
use zeroize::Zeroizing;

/// A passphrase a key file is sealed under: non-empty bytes, wiped on drop.
///
/// **The byte form is part of the file format: a passphrase is its text as UTF-8 in Unicode
/// Normalization Form C (NFC), and nothing else is done to it.** It is never trimmed or case-folded.
/// NFC is fixed because the same visible text arrives as different bytes from different keyboards and
/// terminals (an `é` typed directly is one code point, composed from a dead key it may be two), and a
/// backup restored on another machine must open under the passphrase its owner knows. The rule can
/// never change: a different one would lock out every file sealed under a passphrase it maps
/// differently.
///
/// Both doors apply the rule, so no passphrase can be built that the format does not define: text a
/// person typed comes in through `TryFrom<Zeroizing<String>>`, and bytes through [`new`], which
/// refuses bytes that are not UTF-8 text before putting them in NFC.
///
/// [`new`]: Self::new
///
/// Empty is refused at construction rather than sealed: a file sealed under nothing is plaintext that
/// reports itself as protected.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    /// A passphrase from bytes: UTF-8 text, put in NFC. Refuses bytes that are not UTF-8, since the
    /// format defines a passphrase only as text, and refuses an empty one.
    pub fn new(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, PassphraseError> {
        // Checked in place and moved, never copied: the buffer is handed to the `String` as it is.
        match String::from_utf8(core::mem::take(&mut *bytes)) {
            Ok(text) => Self::try_from(Zeroizing::new(text)),
            Err(error) => {
                // The refused bytes come back out of the error, and are wiped as they drop.
                drop(Zeroizing::new(error.into_bytes()));
                Err(PassphraseError::NotText)
            }
        }
    }

    /// The one constructor both doors end in: `nfc` is already the byte form.
    fn normalized(nfc: Zeroizing<Vec<u8>>) -> Result<Self, PassphraseError> {
        if nfc.is_empty() {
            return Err(PassphraseError::Empty);
        }
        Ok(Self(nfc))
    }

    /// The raw bytes, for the key derivation and nothing else.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Typed text, put in NFC. The normalized form is moved into the passphrase rather than copied, and
/// the text it came from is wiped as it drops.
impl TryFrom<Zeroizing<String>> for Passphrase {
    type Error = PassphraseError;

    fn try_from(text: Zeroizing<String>) -> Result<Self, Self::Error> {
        let mut nfc = nfc(&text);
        Self::normalized(Zeroizing::new(core::mem::take(&mut *nfc).into_bytes()))
    }
}

/// `text` in NFC, in a wiping buffer sized so it never reallocates.
///
/// NFC makes UTF-8 text at most three times longer (UAX #15, section 9), so a buffer of three times
/// the input never grows, and growing is what would leave a copy of the passphrase in freed memory.
/// The normalizer's own small working buffer is outside this crate's reach and is not wiped.
fn nfc(text: &str) -> Zeroizing<String> {
    let mut nfc = Zeroizing::new(String::with_capacity(text.len().saturating_mul(3)));
    // Writing to a `String` cannot fail, so there is no error here to report.
    let _ = ComposingNormalizerBorrowed::new_nfc().normalize_to(text, &mut *nfc);
    nfc
}

/// Redacted: a passphrase never reaches a log through `{:?}`.
impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(..)")
    }
}

/// Why a passphrase could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PassphraseError {
    /// Nothing was given. A file sealed under nothing is plaintext that reports itself as protected.
    #[error("a passphrase cannot be empty")]
    Empty,
    /// The bytes are not UTF-8 text, and a passphrase is defined only as text.
    #[error("a passphrase must be text (UTF-8)")]
    NotText,
}

#[cfg(test)]
#[path = "passphrase_tests.rs"]
mod passphrase_tests;
