use core::fmt;
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use futures_core::Stream;
use url::Url;

/// The path carrying a session's bytes: straight to the peer, or through a relay.
///
/// This answers the single most reassuring question a p2p tool can: "am I actually direct, or bouncing
/// off a relay?" It names the ONE path the transport has selected for application data, never the set
/// of paths it holds open: a transport that keeps a relay path open as a standby beside a direct one is
/// [`Direct`](Self::Direct), because that is where the bytes go. The selection can change over a
/// session's life: a connection often starts [`Relayed`](Self::Relayed) and moves to
/// [`Direct`](Self::Direct) as hole-punching completes, so a reader treats it as the CURRENT path, not
/// a fixed property, and [`PathChanges`] reports each move. A transport that cannot tell reports
/// [`Unknown`](Self::Unknown).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Path {
    /// Peer to peer: bytes flow straight to the remote address, no relay in the middle.
    Direct,
    /// Through the relay named here: the transport has selected the relay path to carry bytes.
    Relayed(Relay),
    /// The transport does not expose its path (in-process, or not yet instrumented), or has no path
    /// selected at this instant.
    #[default]
    Unknown,
}

/// The relay a [`Relayed`](Path::Relayed) path goes through, named by its URL.
///
/// Whatever the transport reports is held as given: it is the address the transport is using, and
/// a reader that shows it to a person renders it as text from elsewhere. Render it with
/// [`Display`](fmt::Display), or read its parts through [`url`](Self::url). Boxed so a [`Path`] stays
/// two words (the box and the variant's tag): a parsed `Url` is large by value, and a path travels
/// inside every [`ConnInfo`] and through every [`PathChanges`] item.
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
/// cannot back. It is a cheap, synchronous accessor snapshotting current state, deliberately OFF the
/// async hot path. Every field describes the same path, the one carrying bytes.
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
/// Returned by `Session::path_changes`. The first item is the path at that moment, so a reader needs
/// no snapshot first and has no order of calls to get wrong. After it, an item arrives at the moment
/// the transport selects a path whose [`Path`] differs from the last item, so a reader that prints it
/// never misses a flip-and-back between two reads of a snapshot. [`Path`] names who carries the bytes
/// (the peer directly, or which relay), not which socket: a move to another relay is an item, a move
/// between two direct addresses is not (the address is [`ConnInfo::remote`]).
///
/// It reports selections, not the gaps between them: after the selected path closes and before the
/// next is selected, `Session::conn_info` reads [`Unknown`](Path::Unknown) and the stream waits for
/// the next selection. A reader that falls behind gets the path selected now, not a replay of the
/// ones it missed. The stream ends after the session closes; a transport whose path never moves, or
/// that cannot tell, says its one path and ends ([`fixed`](Self::fixed)).
///
/// Boxed, `Send + 'static`, and runtime-free like [`HintStream`](crate::HintStream), so a reader can
/// move it to its own task and the caller's executor drives it. It holds no session open.
pub struct PathChanges(Pin<Box<dyn Stream<Item = Path> + Send + 'static>>);

impl PathChanges {
    /// Wrap a transport's own stream of selected paths.
    pub fn new(stream: impl Stream<Item = Path> + Send + 'static) -> Self {
        Self(Box::pin(stream))
    }

    /// A stream that says `path` and ends: the construction for "this path never moves, or no one can
    /// say when it does".
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
