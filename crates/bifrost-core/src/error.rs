/// A transport-neutral error, preserving the underlying cause by source.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Dialing a peer failed.
    #[error("connect to peer")]
    Connect(#[source] BoxError),
    /// Accepting an inbound session failed.
    #[error("accept session")]
    Accept(#[source] BoxError),
    /// Opening or accepting a stream failed.
    #[error("stream")]
    Stream(#[source] BoxError),
    /// The transport has shut down.
    #[error("transport closed")]
    Closed,
}

/// A boxed underlying error, kept as the source of an [`Error`].
pub type BoxError = Box<dyn core::error::Error + Send + Sync + 'static>;
