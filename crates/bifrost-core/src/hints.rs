use core::fmt;
use core::future::poll_fn;
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use futures_core::Stream;

use crate::Error;

/// One address update for a node, delivered by a source subscription.
///
/// State, not an event: every variant says what the source holds NOW, so a consumer that missed the
/// items before this one has lost nothing it needs, and a source never has to queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrUpdate {
    /// The complete current hint set for the node, non-empty when present. Replaces, never merges:
    /// a consumer keeps only the latest set, so a source that changes its mind costs no accumulation.
    Hints(Vec<SocketAddr>),
    /// The node has no live hints (expiry or withdrawal). Cache maintenance; never attempt control.
    ///
    /// Only ever follows a [`Hints`](Self::Hints) on the same stream: a subscriber is never told
    /// about the loss of something it was never told it had. A consumer drops the hints it held and
    /// nothing else; a session already established is not this item's concern, because a removal
    /// is a claim anyone on the source's network can forge.
    Removed,
    /// This source has completed its first window; an empty answer now is final for this source.
    ///
    /// The readiness signal, as data. At most once per subscription, and only when nothing else has
    /// been said first. The source keeps watching: a later `Hints` is still possible.
    Settled,
}

/// A conflated per-node hint feed: the value [`Discovery::subscribe`](crate::Discovery::subscribe)
/// returns and a transport consumes.
///
/// Named rather than a bare alias so the constructors and helpers a source, a composer, and a dial
/// all need have one home. Boxed so a composer can store the feeds it merges and a transport can
/// hold one past the call that received it; `Send + 'static` so either can move it to another task.
/// It names no runtime: [`Stream`] is the only contract, and the caller's executor drives it.
///
/// A feed starts no work of its own. Dropping it is the source's signal to stop anything pending
/// for this node, and no item it yields may cause a dial: what the consumer does with an item, and
/// how long it waits for one, is the consumer's call alone.
pub struct HintStream(Pin<Box<dyn Stream<Item = Result<AddrUpdate, Error>> + Send + 'static>>);

impl HintStream {
    /// Wrap a source's own stream.
    ///
    /// The stream must be state-shaped: when its consumer is slow, it yields the latest state for
    /// the node, never a backlog of every change between polls.
    pub fn new(stream: impl Stream<Item = Result<AddrUpdate, Error>> + Send + 'static) -> Self {
        Self(Box::pin(stream))
    }

    /// A stream that has already ended: the construction for "no source can say more".
    pub fn ended() -> Self {
        Self::new(Once(None))
    }

    /// A stream that says one thing and ends: a source whose answer can never change.
    pub fn once(update: AddrUpdate) -> Self {
        Self::new(Once(Some(update)))
    }

    /// Await the first observation, or the end of the stream.
    ///
    /// Unbounded by design: the caller that awaits this owns the deadline, since a source can be
    /// silent for as long as it likes and must never be the only bound on a dial.
    pub async fn first(mut self) -> Option<Result<AddrUpdate, Error>> {
        poll_fn(|cx| self.0.as_mut().poll_next(cx)).await
    }

    /// The observation the stream holds at this instant, without waiting for one.
    ///
    /// `None` means nothing is ready, whether the source is still looking or has ended; a consumer
    /// that must not wait treats both alike and proceeds with what it already holds.
    pub fn ready(mut self) -> Option<Result<AddrUpdate, Error>> {
        match self
            .0
            .as_mut()
            .poll_next(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(item) => item,
            Poll::Pending => None,
        }
    }
}

impl Stream for HintStream {
    type Item = Result<AddrUpdate, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

impl fmt::Debug for HintStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HintStream").finish_non_exhaustive()
    }
}

/// What a feed has told its subscriber, which turns a source's current state into the one update
/// worth sending.
///
/// The grammar of a feed lives here once, so every state-shaped source speaks it the same way: a
/// feed speaks only on a change, says [`Removed`](AddrUpdate::Removed) only after
/// [`Hints`](AddrUpdate::Hints), and says [`Settled`](AddrUpdate::Settled) at most once and only
/// as its first word. A source re-reads what it holds on every wake and asks this what to say, so a
/// burst of changes between two polls costs one read and yields the latest state.
///
/// Opaque, and made only by [`Default`], so every feed starts having said nothing: a source cannot
/// begin mid-grammar and silence its own first answer or skip its `Settled`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Latest(Said);

/// The states behind [`Latest`], private so the grammar has no way around it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum Said {
    /// Nothing yet: the first answer is still being held.
    #[default]
    Nothing,
    /// The last hint set the subscriber was given.
    Hints(Vec<SocketAddr>),
    /// An empty answer: settled, or removed after hints.
    Empty,
}

impl Latest {
    /// The update for a source that now holds `hints` (empty for none), or `None` when there is
    /// nothing new to say. `settled` is whether the source may call an empty answer final yet.
    /// Records what it returns, so the next call compares against it.
    pub fn say(&mut self, hints: Vec<SocketAddr>, settled: bool) -> Option<AddrUpdate> {
        let update = match (&self.0, hints.is_empty()) {
            (Said::Hints(said), false) if *said == hints => return None,
            (_, false) => AddrUpdate::Hints(hints),
            (Said::Hints(_), true) => AddrUpdate::Removed,
            (Said::Nothing, true) if settled => AddrUpdate::Settled,
            (Said::Nothing | Said::Empty, true) => return None,
        };
        self.0 = match &update {
            AddrUpdate::Hints(hints) => Said::Hints(hints.clone()),
            AddrUpdate::Removed | AddrUpdate::Settled => Said::Empty,
        };
        Some(update)
    }

    /// Whether nothing has been said yet: the one state in which a source still owes its first
    /// answer, so the one in which the end of its settle window is itself worth waking for.
    pub fn said_nothing(&self) -> bool {
        self.0 == Said::Nothing
    }
}

/// At most one item, then the end. `None` from the start is the already-ended stream.
struct Once(Option<AddrUpdate>);

impl Stream for Once {
    type Item = Result<AddrUpdate, Error>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.take().map(Ok))
    }
}
