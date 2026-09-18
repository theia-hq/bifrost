//! Why a peer refused a stream, as far as the DIALER may know.
//!
//! The refusal class lives here, in the lowest crate both ends of a stream already depend on: the
//! wire encoding stays in the tunnel crate that writes it, the host's finer cause stays host-side,
//! and a consumer MATCHES the variant instead of parsing formatted text. See [`Refusal`] for the
//! anti-oracle rule this type is shaped around.

/// Why the peer refused a stream, as far as the DIALER may know.
///
/// `NotAdmitted` is deliberately ONE payload-free variant: the host's finer
/// cause (nauthy's missing / not-granted / revoked, a disabled service, an
/// absent name) stays host-side, so a stranger, a revoked holder, and a wrong
/// name receive identical bytes and the refusal is neither a revocation nor a
/// service-enumeration oracle. `BadRequest` and `Unavailable`
/// are safe to name: the first is the peer's grammar (public), the second is a
/// post-admission host-resource failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The peer's gate did not admit this dial. No payload, by policy.
    #[error("not admitted: no member badge or capability for this service was accepted")]
    NotAdmitted,
    /// The peer rejected the request shape before any policy ran.
    #[error("bad request: {detail}")]
    BadRequest {
        /// The peer's bounded explanation.
        detail: RefusalDetail,
    },
    /// The host could not complete this dial for a reason of its own, which is NOT a ruling about the
    /// dialer.
    ///
    /// It used to mean the narrower "the peer admitted the dial but could not serve it", so a dialer
    /// could read it as proof of having been admitted. That is gone deliberately. A gate whose
    /// evaluation runs out of time decided nothing about the caller's authority, and telling them they
    /// were not admitted is a lie they act on: they stop retrying and go hunting for a credential
    /// nothing rejected. So a pre-admission failure of the host's own lands here too, and the variant
    /// now means only "this is about us, not about you". A caller retries it; it is never an
    /// authorization outcome and must never be recorded as one.
    #[error("unavailable: {detail}")]
    Unavailable {
        /// The peer's bounded explanation.
        detail: RefusalDetail,
    },
}

/// A bounded human-readable detail on a non-uniform refusal.
///
/// The cap is declared ONCE here; every wire codec that carries a detail
/// derives its writer and reader bounds from `MAX_LEN`, so a writer can never
/// emit a frame its own reader rejects. `bounded` is the writer-side
/// constructor (truncates at a UTF-8 char boundary, never mid-codepoint);
/// `TryFrom` is the validating one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalDetail(String);

impl RefusalDetail {
    /// The longest a detail may be on the wire, in bytes.
    pub const MAX_LEN: usize = 1024;

    /// Bound `text` to [`MAX_LEN`](Self::MAX_LEN) at a UTF-8 char boundary.
    /// A detail is the peer's own prose, so the writer truncates rather than
    /// failing the response; the peer logs the untruncated form.
    pub fn bounded(text: impl Into<String>) -> Self {
        let mut text = text.into();
        if text.len() > Self::MAX_LEN {
            let mut cut = Self::MAX_LEN;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
        }
        Self(text)
    }

    /// The bounded text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for RefusalDetail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for RefusalDetail {
    type Error = RefusalDetailError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > Self::MAX_LEN {
            return Err(RefusalDetailError::TooLong(value.len() as u32));
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<Vec<u8>> for RefusalDetail {
    type Error = RefusalDetailError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() > Self::MAX_LEN {
            return Err(RefusalDetailError::TooLong(bytes.len() as u32));
        }
        String::from_utf8(bytes)
            .map(Self)
            .map_err(|_| RefusalDetailError::NotUtf8)
    }
}

/// Why a wire detail was rejected: a corrupt or hostile frame, never repaired.
#[derive(Debug, thiserror::Error)]
pub enum RefusalDetailError {
    /// The claimed length exceeded [`RefusalDetail::MAX_LEN`].
    #[error("refusal detail too long ({0} bytes)")]
    TooLong(u32),
    /// The bytes were not valid UTF-8.
    #[error("refusal detail was not UTF-8")]
    NotUtf8,
}
