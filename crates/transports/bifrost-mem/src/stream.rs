//! A session's stream halves, and the one signal that ends them all.
//!
//! An in-process stream is a `tokio::io::duplex` pair, which shares nothing with the session that made
//! it: left alone, a held half would keep carrying bytes after its session was closed. So both ends of a
//! session share one [`Severance`], and every half checks it. Once it fires, reads fail with
//! `ConnectionAborted` and writes with `BrokenPipe`, never a clean end, so a transfer the close cut
//! short can never pass for a complete one.

use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use std::sync::Arc;

use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::sync::futures::OwnedNotified;

/// The close signal one session pair shares: sticky once set, and waking every half parked on it.
#[derive(Default)]
pub(crate) struct Severance {
    severed: AtomicBool,
    notify: Arc<Notify>,
}

impl Severance {
    /// End the session: every half fails from now on, and any parked on a read or write is woken.
    pub(crate) fn sever(&self) {
        self.severed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Whether the session was closed.
    pub(crate) fn is_severed(&self) -> bool {
        self.severed.load(Ordering::Acquire)
    }

    /// Resolve once the session is closed.
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

/// Watches one half's [`Severance`] across polls, so a half parked on the duplex is woken by a close.
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

    /// `true` once the session is closed. Otherwise registers the task to be woken by a close and
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
    watch: Watch,
}

/// The writable half of an in-process stream.
pub struct MemWrite {
    half: io::WriteHalf<io::DuplexStream>,
    watch: Watch,
}

/// Split one duplex end into the two halves a session hands out, both watching `severance`.
pub(crate) fn halves(end: io::DuplexStream, severance: &Arc<Severance>) -> (MemWrite, MemRead) {
    let (read, write) = io::split(end);
    (
        MemWrite {
            half: write,
            watch: Watch::new(Arc::clone(severance)),
        },
        MemRead {
            half: read,
            watch: Watch::new(Arc::clone(severance)),
        },
    )
}

fn aborted() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "session closed")
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "session closed")
}

impl AsyncRead for MemRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.watch.severed(cx) {
            return Poll::Ready(Err(aborted()));
        }
        Pin::new(&mut this.half).poll_read(cx, buf)
    }
}

impl AsyncWrite for MemWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.watch.severed(cx) {
            return Poll::Ready(Err(broken()));
        }
        Pin::new(&mut this.half).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.watch.severed(cx) {
            return Poll::Ready(Err(broken()));
        }
        Pin::new(&mut this.half).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.watch.severed(cx) {
            return Poll::Ready(Err(broken()));
        }
        Pin::new(&mut this.half).poll_shutdown(cx)
    }
}

impl core::fmt::Debug for MemRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemRead")
            .field("severed", &self.watch.severance.is_severed())
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for MemWrite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemWrite")
            .field("severed", &self.watch.severance.is_severed())
            .finish_non_exhaustive()
    }
}
