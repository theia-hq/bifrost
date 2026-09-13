use std::io;

use bifrost_core::{Error, NodeId};

/// Why a sealed wrapper operation failed.
///
/// The wrapper maps handshake, dial, and open-path failures to typed variants so a consumer can
/// match the cause without parsing a message. Failures below the wrapper (dial, accept, stream)
/// keep their [`bifrost_core::Error`] class through [`Inner`](Self::Inner); everything else is a
/// wrapper protocol or handshake failure. A fatal frame is not a value here: transport mode has no
/// place to return one, so it tears the session down, fails pending reads closed, and wakes
/// `wait_closed`.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    /// The inner transport is bound under a different identity than the wrapper's seed names.
    ///
    /// One address carries one [`NodeId`]; a wrapper whose identity differs from its inner cannot
    /// be routed to and would dial the wrong key, so construction refuses instead.
    #[error("inner transport identity differs from the wrapper identity")]
    IdentityMismatch {
        /// The identity the wrapper's seed derives.
        local: NodeId,
        /// The identity the inner transport reports.
        inner: NodeId,
    },

    /// The fixed handshake pattern is unavailable in this build.
    ///
    /// Cannot occur while the crate pins its `snow` features; the variant exists so construction
    /// never panics.
    #[error("handshake pattern unavailable")]
    UnsupportedPattern,

    /// The peer's first bytes were not the wrapper tag: a bare inner peer, or a version mismatch.
    #[error("peer did not present the wrapper tag")]
    BadTag,

    /// The handshake did not complete within its deadline.
    #[error("handshake timed out")]
    HandshakeTimeout,

    /// A message length exceeded the wrapper's bound.
    ///
    /// Checked from the length prefix before any allocation, for both the handshake and the frame
    /// reader.
    #[error("message of {len} bytes exceeds the {max}-byte bound")]
    MessageTooLarge {
        /// The length the peer announced.
        len: usize,
        /// The largest length the wrapper accepts at that point.
        max: usize,
    },

    /// `snow` rejected a handshake message: a forged or replayed flight, or a moved transcript.
    #[error("noise handshake")]
    Handshake(#[source] snow::Error),

    /// The peer signed with a key other than the identity that was dialed.
    ///
    /// The dialer checks the responder's signature under the dialed [`NodeId`]; a claimed signer
    /// that differs is a protocol failure, not an identity.
    #[error("peer signer differs from the dialed identity")]
    SignerMismatch {
        /// The identity the dialer addressed.
        dialed: NodeId,
        /// The identity the peer claimed in its payload.
        claimed: NodeId,
    },

    /// The peer's signature did not verify over this transcript under its claimed identity.
    #[error("handshake signature did not verify")]
    SignatureInvalid,

    /// A handshake or frame payload was not the fixed shape the protocol defines.
    #[error("malformed payload")]
    MalformedPayload,

    /// The session reached its cap on concurrently open streams.
    #[error("stream limit reached")]
    TooManyStreams,

    /// The system RNG failed while generating a fresh handshake static.
    #[error("system rng unavailable")]
    RngUnavailable,

    /// The handshake produced key material of an unexpected length.
    #[error("unexpected key length")]
    KeyLength,

    /// Reading or writing the inner stream failed.
    #[error("inner stream io")]
    Io(#[from] io::Error),

    /// The inner transport failed below the wrapper.
    #[error("inner transport")]
    Inner(#[from] Error),

    /// The session has closed.
    #[error("session closed")]
    Closed,
}

impl NoiseError {
    /// Classify this failure as a dial failure.
    pub(crate) fn into_connect(self) -> Error {
        Error::Connect(Box::new(self))
    }

    /// Classify this failure as an accept failure.
    pub(crate) fn into_accept(self) -> Error {
        Error::Accept(Box::new(self))
    }

    /// Classify this failure as a stream failure.
    pub(crate) fn into_stream(self) -> Error {
        Error::Stream(Box::new(self))
    }
}
