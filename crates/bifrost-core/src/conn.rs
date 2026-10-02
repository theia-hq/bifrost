use core::fmt;
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use futures_core::Stream;
use url::Url;

/// The path carrying a session's bytes: straight to the peer, or through a relay.
///
/// It names the one path the transport has selected for application data, not every path it holds
/// open: a direct path with a relay kept open as a standby is [`Direct`](Self::Direct). The selection
/// can change during a session, often from [`Relayed`](Self::Relayed) to [`Direct`](Self::Direct)
/// once hole-punching succeeds, and [`PathChanges`] reports each change. A transport that cannot tell
/// reports [`Unknown`](Self::Unknown).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Path {
    /// Peer to peer: bytes flow straight to the remote address, no relay in the middle.
    Direct,
    /// Through the relay named here.
    Relayed(Relay),
    /// The transport does not report its path (an in-process transport has none), has no path selected
    /// right now, or has selected a kind of path this crate does not name.
    #[default]
    Unknown,
}

/// The relay a [`Relayed`](Path::Relayed) path goes through, named by its URL.
///
/// The URL is as the transport reports it, not vetted by this crate, and it can come from the peer.
/// Render it with [`Display`](fmt::Display), or read its parts through [`url`](Self::url).
// Boxed so a `Path` stays two words (the box and the variant's tag): a parsed `Url` is large by
// value, and a path travels inside every `ConnInfo` and through every `PathChanges` item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay(Box<Url>);

impl Relay {
    /// The relay's URL, for a reader that needs a part of it, such as the host alone.
    pub fn url(&self) -> &Url {
        let Self(url) = self;
        url
    }
}

impl From<Url> for Relay {
    fn from(url: Url) -> Self {
        Self(Box::new(url))
    }
}

impl fmt::Display for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(url) = self;
        f.write_str(url.as_str())
    }
}

/// A best-effort snapshot of how a session reaches its peer, for a status or diagnostics consumer.
///
/// Best-effort by design: every field a transport cannot determine is absent (the [`Path`] is
/// [`Unknown`](Path::Unknown), the rest are `None`), so this never fabricates a reassuring answer it
/// cannot back. It is a cheap, synchronous accessor snapshotting current state, off the async hot
/// path. Every field describes the same path, the one carrying bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnInfo {
    /// The path carrying bytes: direct, through a named relay, or unknown.
    pub path: Path,
    /// The transport's current round-trip estimate for that path, if it tracks one.
    pub rtt: Option<Duration>,
    /// The peer's socket address on a direct path, if the transport exposes it. A relayed path names
    /// its relay in [`Path::Relayed`] instead.
    pub remote: Option<SocketAddr>,
}

/// The path carrying a session's bytes: the one in force when the stream is made, then each change.
///
/// Returned by `Session::path_changes`. After the first item, an item arrives when the transport
/// selects a path whose [`Path`] differs from the last item, so a change and its reversal between two
/// reads of `Session::conn_info` both show. [`Path`] names who carries the bytes (the peer directly, or
/// which relay), not which socket: a move to another relay is an item, a move between two direct
/// addresses is not (the address is [`ConnInfo::remote`]).
///
/// It reports selections, not the gaps between them: after the selected path closes and before the
/// next is selected, `Session::conn_info` reads [`Unknown`](Path::Unknown) and the stream waits. A
/// reader that falls behind gets the path selected now, not the ones it missed. The stream ends after
/// the session closes; a transport whose path never moves, or that cannot tell, yields its one path
/// and ends ([`fixed`](Self::fixed)).
///
/// `Send + 'static` and runtime-free like [`HintStream`](crate::HintStream): move it to its own task,
/// and the caller's executor drives it. It does not keep the session open.
pub struct PathChanges(Pin<Box<dyn Stream<Item = Path> + Send + 'static>>);

impl PathChanges {
    /// Wrap a transport's stream of selected paths. [`PathChanges`] states the rules the stream must
    /// keep; nothing here checks them.
    pub fn new(stream: impl Stream<Item = Path> + Send + 'static) -> Self {
        Self(Box::pin(stream))
    }

    /// A stream that yields `path` once and ends, for a session whose path never moves or that cannot
    /// tell.
    pub fn fixed(path: Path) -> Self {
        Self::new(Fixed(Some(path)))
    }
}

impl Stream for PathChanges {
    type Item = Path;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

impl fmt::Debug for PathChanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PathChanges").finish_non_exhaustive()
    }
}

/// The stream behind [`PathChanges::fixed`].
struct Fixed(Option<Path>);

impl Stream for Fixed {
    type Item = Path;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.take())
    }
}
