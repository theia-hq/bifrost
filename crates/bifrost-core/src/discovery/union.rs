use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};

use futures_core::Stream;

use crate::{AddrUpdate, Error, HintStream, Latest};

/// The merged feed behind [`Layered`](super::Layered): two subscriptions, one union.
///
/// Poll-driven with no task of its own: each poll drains whatever both sources have ready, folds it
/// into per-source state, and says at most one thing about the union. Draining before speaking is
/// the conflation: a burst from either source becomes one item carrying the latest union, never a
/// queue.
///
/// A failed source counts as ended and keeps its last hints, so one source's failure never fails a
/// dial the other can serve. Only when every source has stopped and nothing is held does the union
/// surface a failure, once, so a union fails exactly where a lone source would have.
pub(super) struct Union {
    primary: Side,
    secondary: Side,
    /// What this feed last told its subscriber, so it speaks only on a change.
    said: Latest,
}

impl Union {
    pub(super) fn new(primary: HintStream, secondary: HintStream) -> Self {
        Self {
            primary: Side::new(primary),
            secondary: Side::new(secondary),
            said: Latest::default(),
        }
    }

    /// Primary hints first, then the secondary's minus any the primary already holds.
    fn hints(&self) -> Vec<SocketAddr> {
        let mut hints = self.primary.held.clone();
        for addr in &self.secondary.held {
            if !hints.contains(addr) {
                hints.push(*addr);
            }
        }
        hints
    }

    fn live(&self) -> bool {
        self.primary.live() || self.secondary.live()
    }

    fn answered(&self) -> bool {
        self.primary.answered() && self.secondary.answered()
    }

    /// A union may call an empty answer final once every source has answered, and only while a
    /// source can still speak: a union whose every source has ended says so by ending.
    fn settled(&self) -> bool {
        self.answered() && self.live()
    }
}

impl Stream for Union {
    type Item = Result<AddrUpdate, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        // Both sides drain on every poll, so neither is starved by the other being busy.
        let primary = this.primary.drain(cx);
        let secondary = this.secondary.drain(cx);
        if primary == Drain::Spent || secondary == Drain::Spent {
            // A side still has items, so what the union holds may already be stale: say nothing
            // yet, and ask to be polled again rather than keep the thread.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let (hints, settled) = (this.hints(), this.settled());
        let empty = hints.is_empty();
        if let Some(update) = this.said.say(hints, settled) {
            return Poll::Ready(Some(Ok(update)));
        }
        // Every live side returned `Pending` from its drain, so each has registered this waker.
        if this.live() {
            return Poll::Pending;
        }
        // Every source has stopped. With a hint held, the union ends and the dial uses it; with
        // none, a failure is the reason the dial has nothing, so it is surfaced (the primary's
        // first) rather than letting the dial go bare with no reason given. Both are taken, so the
        // next poll ends.
        let (first, second) = (this.primary.failed.take(), this.secondary.failed.take());
        match first.or(second) {
            Some(err) if empty => Poll::Ready(Some(Err(err))),
            _ => Poll::Ready(None),
        }
    }
}

/// One source's side of the union: its feed while it can still speak, and what it last held.
struct Side {
    /// `None` once the source has ended or failed.
    feed: Option<HintStream>,
    /// Why the source stopped, when it stopped by failing. Held until the union knows whether
    /// the failure matters: it does only if every source stops with nothing held.
    failed: Option<Error>,
    /// Whether the source has said anything yet.
    heard: bool,
    /// The source's latest complete hint set. Kept when the feed ends: an end means "no more
    /// updates", not "the node is gone", so the last word stands.
    held: Vec<SocketAddr>,
}

impl Side {
    fn new(feed: HintStream) -> Self {
        Self {
            feed: Some(feed),
            failed: None,
            heard: false,
            held: Vec::new(),
        }
    }

    fn live(&self) -> bool {
        self.feed.is_some()
    }

    /// A source has answered once it has said anything, or can no longer say anything.
    fn answered(&self) -> bool {
        self.heard || !self.live()
    }

    /// Take every item the source has ready, keeping only the latest state, until it is pending
    /// (which registers the waker), ended, or out of budget.
    fn drain(&mut self, cx: &mut Context<'_>) -> Drain {
        for _ in 0..DRAIN_BUDGET {
            let Some(feed) = self.feed.as_mut() else {
                return Drain::Done;
            };
            match Pin::new(feed).poll_next(cx) {
                Poll::Pending => return Drain::Done,
                Poll::Ready(Some(Ok(update))) => {
                    self.heard = true;
                    match update {
                        AddrUpdate::Hints(hints) => self.held = hints,
                        AddrUpdate::Removed => self.held.clear(),
                        AddrUpdate::Settled => {}
                    }
                }
                // A failed source is a source that can say no more, as an ended one is: one
                // source's failure must not fail a dial the other source can still serve.
                Poll::Ready(Some(Err(err))) => {
                    self.feed = None;
                    self.failed = Some(err);
                }
                Poll::Ready(None) => self.feed = None,
            }
        }
        Drain::Spent
    }
}

/// How one side's drain finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drain {
    /// The side is pending (its waker registered) or ended: what it holds is its latest state.
    Done,
    /// The side hit [`DRAIN_BUDGET`] with items still coming, and registered no waker.
    Spent,
}

/// The most items one poll takes from one source.
///
/// A state-shaped source has at most a few items ready at once, so a conforming one never reaches
/// this. It bounds a source that is ready on every poll and never returns `Pending`: such a source
/// costs one bounded slice of the executor per poll, not the whole thread for ever. Sized above
/// any burst a conforming source can build, since a spent drain holds the union's answer.
const DRAIN_BUDGET: usize = 128;
