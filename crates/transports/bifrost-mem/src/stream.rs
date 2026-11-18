//! A session's stream halves, the signal that ends them all, and the one that ends one direction.
//!
//! An in-process stream is a `tokio::io::duplex` pair, which shares nothing with the session that made
//! it: left alone, a held half would keep carrying bytes after its session was closed. So both ends of a
//! session share one [`Severance`], and every half checks it. Once it fires, reads fail with
//! `ConnectionAborted` and writes with `BrokenPipe`, never a clean end, so a transfer the close cut
//! short can never pass for a complete one.
//!
//! Each direction of a stream has a [`Severance`] of its own, shared by the half that writes it and
//! the peer's half that reads it. An abort fires only that one: the peer's read fails with
//! `ConnectionReset` and the aborted writer's later writes with `BrokenPipe`, while the opposite
//! direction and every other stream carry on, as a QUIC stream reset leaves them.
//!
//! Each direction also has a [`Reading`], moved by the peer's reader and watched by the writer's
//! `delivered`. A close discards bytes the reader has not read, so here the peer holds a stream only
//! once it has read it to the end, and `delivered` waits for exactly that.

use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker, ready};
use std::sync::Arc;

use bifrost_transport::WriteEnd;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::futures::OwnedNotified;
use tokio::sync::{Notify, watch};

/// A sticky end signal that wakes every half parked on it: one per session pair for a close, and one
/// per stream direction for an abort.
#[derive(Default)]
pub(crate) struct Severance {
    severed: AtomicBool,
    notify: Arc<Notify>,
}

impl Severance {
    /// Fire the signal: every half watching it fails from now on, and any parked on it is woken.
    pub(crate) fn sever(&self) {
        self.severed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Whether the signal has fired.
    pub(crate) fn is_severed(&self) -> bool {
        self.severed.load(Ordering::Acquire)
    }

    /// Resolve once the signal fires.
    pub(crate) async fn severed(&self) {
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Registered before the check, so a close between the two still wakes this.
        notified.as_mut().enable();
        if self.is_severed() {
            return;
        }
        notified.await;
    }
}

/// Watches one [`Severance`] across polls, so a half parked on the duplex is woken when it fires.
struct Watch {
    severance: Arc<Severance>,
    /// Held across polls: a fresh `Notified` per poll would miss a close between two of them.
    waiter: Option<Pin<Box<OwnedNotified>>>,
}

impl Watch {
    fn new(severance: Arc<Severance>) -> Self {
        Self {
            severance,
            waiter: None,
        }
    }

    /// `true` once the signal has fired. Otherwise registers the task to be woken when it fires and
    /// returns `false`. Interest is registered before the flag is read, never after.
    fn severed(&mut self, cx: &mut Context<'_>) -> bool {
        let waiter = self
            .waiter
            .get_or_insert_with(|| Box::pin(Arc::clone(&self.severance.notify).notified_owned()));
        waiter.as_mut().enable();
        if self.severance.is_severed() {
            return true;
        }
        if waiter.as_mut().poll(cx).is_ready() {
            self.waiter = None;
            return true;
        }
        false
    }
}

/// The readable half of an in-process stream.
pub struct MemRead {
    half: io::ReadHalf<io::DuplexStream>,
    session: Watch,
    /// The peer writer's abort signal for this direction.
    stream: Watch,
    /// How far this reader has got, for the peer writer's `delivered`.
    reading: watch::Sender<Reading>,
}

/// The writable half of an in-process stream.
pub struct MemWrite {
    half: io::WriteHalf<io::DuplexStream>,
    session: Watch,
    /// This direction's abort signal. Only this half fires it, through `&mut self`, so no write can be
    /// parked across the abort and a plain flag check is enough here; the peer's read is the side
    /// that has to be woken.
    stream: Arc<Severance>,
    end: End,
    /// How far the peer's reader has got with this direction.
    reading: watch::Receiver<Reading>,
}

/// How far a direction's reader has got. Moves once, from `Open`, and never back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading {
    /// Still reading, or not yet started.
    Open,
    /// Read the clean end: every byte written has been read.
    ReadToEnd,
    /// Dropped before the end, so the rest will never be read.
    Gone,
}

/// How far a write half has got toward its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// Still open: an abort fires the signal.
    Open,
    /// `shutdown` returned success, so the peer reads the clean end and an abort does nothing.
    Finished,
}

/// Build both ends of one stream from a duplex pair: each end's halves watch the session's
/// `severance`, and each direction gets its own abort signal, shared by its writer and the reader at
/// the other end.
pub(crate) fn ends(
    (near, far): (io::DuplexStream, io::DuplexStream),
    severance: &Arc<Severance>,
) -> ((MemWrite, MemRead), (MemWrite, MemRead)) {
    let outward = Arc::new(Severance::default());
    let inward = Arc::new(Severance::default());
    // A watch, not a `Notify`: a writer may ask for delivery long after its reader reached the end,
    // and a watch keeps the last state for it.
    let (outward_read, outward_wait) = watch::channel(Reading::Open);
    let (inward_read, inward_wait) = watch::channel(Reading::Open);
    (
        halves(
            near,
            severance,
            (&outward, outward_wait),
            (&inward, inward_read),
        ),
        halves(
            far,
            severance,
            (&inward, inward_wait),
            (&outward, outward_read),
        ),
    )
}

/// Split one duplex end into the two halves a session hands out: the writer fires `writes` and waits
/// on its direction's reader, the reader watches `reads` and reports how far it got, and both watch
/// the session's `severance`.
fn halves(
    end: io::DuplexStream,
    severance: &Arc<Severance>,
    (writes, delivery): (&Arc<Severance>, watch::Receiver<Reading>),
    (reads, reading): (&Arc<Severance>, watch::Sender<Reading>),
) -> (MemWrite, MemRead) {
    let (read, write) = io::split(end);
    (
        MemWrite {
            half: write,
            session: Watch::new(Arc::clone(severance)),
            stream: Arc::clone(writes),
            end: End::Open,
            reading: delivery,
        },
        MemRead {
            half: read,
            session: Watch::new(Arc::clone(severance)),
            stream: Watch::new(Arc::clone(reads)),
            reading,
        },
    )
}

fn aborted() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "session closed")
}

fn reset() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "stream aborted")
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "session closed")
}

fn broken_by_abort() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "stream aborted")
}

impl MemWrite {
    /// Why this half can no longer write, if it cannot: a closed session first, then an abort.
    fn ended(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if self.session.severed(cx) {
            return Some(broken());
        }
        self.stream.is_severed().then(broken_by_abort)
    }
}

impl WriteEnd for MemWrite {
    // Fires this direction's signal and nothing else: the peer's read of it fails from now on, and any
    // bytes still in the duplex are never read, the in-process form of a reset discarding them. After
    // a successful shutdown it does nothing, so the clean end stands, as on every backend.
    fn abort(&mut self) {
        if self.end == End::Finished {
            return;
        }
        self.stream.sever();
    }

    // An open half is finished by its own drop, below. The reader's end is checked first, so a close
    // or a dropped reader after the stream was read to its end cannot turn a delivery into an error.
    fn delivered(self) -> impl Future<Output = io::Result<()>> + Send + 'static {
        // Only an abort before a successful shutdown fires this direction's signal.
        let cut = self.stream.is_severed();
        let mut reading = self.reading.clone();
        let session = Arc::clone(&self.session.severance);
        drop(self);
        async move {
            if cut {
                return Err(reset());
            }
            tokio::select! {
                biased;
                read = reading.wait_for(|read| *read != Reading::Open) => match read.map(|read| *read) {
                    Ok(Reading::ReadToEnd) => Ok(()),
                    _ => Err(io::Error::new(io::ErrorKind::BrokenPipe, "peer stopped reading")),
                },
                () = session.severed() => Err(aborted()),
            }
        }
    }
}

impl AsyncRead for MemRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.session.severed(cx) {
            return Poll::Ready(Err(aborted()));
        }
        if this.stream.severed(cx) {
            return Poll::Ready(Err(reset()));
        }
        // A read with room that fills nothing is the clean end; one into a full buffer is not.
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let read = ready!(Pin::new(&mut this.half).poll_read(cx, buf));
        if read.is_ok() && room && buf.filled().len() == before {
            this.reading
                .send_if_modified(|reading| reach(reading, Reading::ReadToEnd));
        }
        Poll::Ready(read)
    }
}

/// Move a direction's reading on from `Open` to `to`, and report whether it moved: a later read or
/// the reader's drop never undoes an end already read.
fn reach(reading: &mut Reading, to: Reading) -> bool {
    let moved = *reading == Reading::Open;
    if moved {
        *reading = to;
    }
    moved
}

// A reader dropped before the end will never read the rest, so the peer writer's `delivered` fails
// rather than waits.
impl Drop for MemRead {
    fn drop(&mut self) {
        self.reading
            .send_if_modified(|reading| reach(reading, Reading::Gone));
    }
}

impl AsyncWrite for MemWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(ended) = this.ended(cx) {
            return Poll::Ready(Err(ended));
        }
        Pin::new(&mut this.half).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(ended) = this.ended(cx) {
            return Poll::Ready(Err(ended));
        }
        Pin::new(&mut this.half).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(ended) = this.ended(cx) {
            return Poll::Ready(Err(ended));
        }
        let done = ready!(Pin::new(&mut this.half).poll_shutdown(cx));
        if done.is_ok() {
            this.end = End::Finished;
        }
        Poll::Ready(done)
    }
}

// A split half shares its duplex with the read half, so dropping the writer alone would close
// nothing while the reader is held: the peer would wait forever instead of reading the clean end a
// dropped QUIC send stream gives. Shutting the write side here makes a drop end the stream, with
// buffered bytes still delivered first. The duplex's shutdown never pends and needs no waker, and
// after an abort the peer's read still fails, since it checks the abort before the pipe.
impl Drop for MemWrite {
    fn drop(&mut self) {
        let mut cx = Context::from_waker(Waker::noop());
        let _ready = Pin::new(&mut self.half).poll_shutdown(&mut cx);
    }
}

impl core::fmt::Debug for MemRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemRead")
            .field("severed", &self.session.severance.is_severed())
            .field("aborted", &self.stream.severance.is_severed())
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for MemWrite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemWrite")
            .field("severed", &self.session.severance.is_severed())
            .field("aborted", &self.stream.is_severed())
            .finish_non_exhaustive()
    }
}
