//! The wrapper session: one Noise channel over one inner stream, framed logical streams inside.
//!
//! After the handshake completes, the inner stream carries length-prefixed Noise messages whose
//! plaintext is a typed frame: `OPEN`, `DATA`, `FIN`, or `RESET` with a stream id. A session runs
//! exactly two tasks, one encrypting outbound frames and one decrypting inbound frames; application
//! streams are bounded channels so a stalled reader propagates backpressure to the peer instead of
//! growing memory.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Poll};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex as StdMutex, Weak};

use bifrost_core::{ConnInfo, Error, NodeId};
use bifrost_transport::{Sealed, Session};
use snow::TransportState;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;

use crate::error::NoiseError;
use crate::handshake::{self, Established};
use crate::wire;

/// Frames the outbound queue holds before `open_bi`/write wait.
const FRAME_QUEUE: usize = 64;
/// Chunks one stream's inbound queue holds before the reader task waits.
const STREAM_QUEUE: usize = 8;
/// Streams the session will hold open for `accept_bi` before the reader task waits.
const ACCEPT_QUEUE: usize = 8;
/// Streams one session may hold open at once. A slot is released when the last half of a stream
/// drops, so a long-lived session that opens and closes streams does not run out.
const MAX_STREAMS: u32 = 64;
/// The largest plaintext frame, headers included.
const MAX_FRAME_PLAINTEXT: usize = 16 * 1024;
/// `kind` byte plus the big-endian stream id.
const FRAME_HEADER: usize = 5;
/// The largest application chunk one `DATA` frame carries.
const MAX_CHUNK: usize = MAX_FRAME_PLAINTEXT - FRAME_HEADER;
/// The largest ciphertext one frame can be: plaintext plus the AEAD tag.
const MAX_FRAME_CIPHERTEXT: usize = MAX_FRAME_PLAINTEXT + 16;

const KIND_OPEN: u8 = wire::FRAME_OPEN;
const KIND_DATA: u8 = wire::FRAME_DATA;
const KIND_FIN: u8 = wire::FRAME_FIN;
const KIND_RESET: u8 = wire::FRAME_RESET;

/// Which side of the handshake this session ran, fixing stream id parity.
#[derive(Clone, Copy)]
pub(crate) enum Role {
    /// The dialer: even ids.
    Initiator,
    /// The acceptor: odd ids.
    Responder,
}

impl Role {
    /// The id parity this side allocates.
    fn local_parity(self) -> u32 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }

    /// The id parity the peer allocates.
    fn peer_parity(self) -> u32 {
        self.local_parity() ^ 1
    }

    /// The first id this side allocates.
    fn next_id(self) -> u32 {
        self.local_parity()
    }
}

/// A logical stream opened by the peer, waiting for `accept_bi`.
struct Inbound {
    id: u32,
    rx: mpsc::Receiver<Chunk>,
    life: Arc<StreamLife>,
}

/// One live stream's lifetime: the last half to drop releases the session's slot, and the sticky
/// `torn` flag records that the session died under it.
///
/// The flag is what makes a teardown fail closed even when a per-stream queue is full and the
/// reset chunk cannot be enqueued: `StreamRead` maps the queue's end to `ConnectionReset` when the
/// flag is set, so a truncated read never presents as a clean EOF.
pub(crate) struct StreamLife {
    live: Arc<AtomicU32>,
    torn: AtomicBool,
}

impl StreamLife {
    /// Claim a concurrent slot, or `None` when the cap is reached.
    pub(crate) fn acquire(live: &Arc<AtomicU32>) -> Option<Arc<Self>> {
        let open = live.fetch_add(1, Ordering::Relaxed) + 1;
        if open > MAX_STREAMS {
            live.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Arc::new(Self {
            live: Arc::clone(live),
            torn: AtomicBool::new(false),
        }))
    }

    /// Mark the stream torn: its session is gone, so its read ends with a reset, not a clean EOF.
    pub(crate) fn tear(&self) {
        self.torn.store(true, Ordering::Release);
    }

    /// Whether the session died under this stream.
    pub(crate) fn is_torn(&self) -> bool {
        self.torn.load(Ordering::Acquire)
    }
}

impl Drop for StreamLife {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One live route: where a stream's chunks go, and a weak handle to its lifetime for the teardown
/// marker. The handle is weak so the route never keeps a closed stream's slot claimed; only the
/// stream's own halves (and a queued `Inbound`) own the `StreamLife`.
#[derive(Clone)]
struct Route {
    tx: mpsc::Sender<Chunk>,
    life: Weak<StreamLife>,
}

/// The session's death signal.
///
/// Sticky: a `wait_closed` that starts after the pumps exited still observes the death, and
/// `notify_one` stores a permit so a waiter already parked is woken.
struct Exit {
    dead: AtomicBool,
    notify: Notify,
}

impl Exit {
    fn new() -> Self {
        Self {
            dead: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn close(&self) {
        self.dead.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    async fn wait(&self) {
        if self.dead.load(Ordering::Acquire) {
            return;
        }
        let notified = self.notify.notified();
        if self.dead.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

/// One piece of an inbound stream: bytes, or the peer's reset.
pub(crate) enum Chunk {
    Data(Vec<u8>),
    Reset,
}

/// One outbound frame, queued for the writer task.
pub(crate) enum Outbound {
    Open(u32),
    Data(u32, Vec<u8>),
    Fin(u32),
    Reset(u32),
}

impl Outbound {
    /// Encode the frame as `kind || id || payload`.
    fn encode(&self, out: &mut Vec<u8>) {
        let (kind, id, payload) = match self {
            Self::Open(id) => (KIND_OPEN, *id, &[][..]),
            Self::Data(id, payload) => (KIND_DATA, *id, &payload[..]),
            Self::Fin(id) => (KIND_FIN, *id, &[][..]),
            Self::Reset(id) => (KIND_RESET, *id, &[][..]),
        };
        out.clear();
        out.push(kind);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(payload);
    }
}

/// A sealed session: the inner session plus the Noise channel over its first stream.
///
/// `peer()` is the identity the handshake proved, never the inner transport's announcement. The
/// inner session is kept only for `wait_closed` and `conn_info`; its streams are not consulted.
pub struct NoiseSession<S: Session> {
    inner: S,
    peer: NodeId,
    frames: mpsc::Sender<Outbound>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<Inbound>>,
    routes: Arc<StdMutex<HashMap<u32, Route>>>,
    live: Arc<AtomicU32>,
    exit: Arc<Exit>,
    writer: AbortHandle,
    reader: AbortHandle,
    next_id: AtomicU32,
}

impl<S: Session> NoiseSession<S> {
    /// Start the two frame pumps over an established handshake.
    ///
    /// The inner stream halves are owned by the pumps for the whole session, so they must be
    /// `'static`; every concrete backend's halves are.
    pub(crate) fn start(
        inner: S,
        write: S::Write,
        read: S::Read,
        established: Established,
        role: Role,
    ) -> Self
    where
        S::Write: 'static,
        S::Read: 'static,
    {
        let Established { state, peer } = established;
        let state = Arc::new(StdMutex::new(state));
        let (frames, frames_rx) = mpsc::channel(FRAME_QUEUE);
        let (incoming, incoming_rx) = mpsc::channel(ACCEPT_QUEUE);
        let routes = Arc::new(StdMutex::new(HashMap::new()));
        let live = Arc::new(AtomicU32::new(0));
        let exit = Arc::new(Exit::new());

        let writer = tokio::spawn(write_loop(
            write,
            Arc::clone(&state),
            frames_rx,
            Arc::clone(&exit),
        ));
        let writer = writer.abort_handle();
        let reader = tokio::spawn(read_loop(
            read,
            state,
            Dispatch {
                routes: Arc::clone(&routes),
                incoming,
                frames: frames.clone(),
                live: Arc::clone(&live),
            },
            role,
            writer.clone(),
            Arc::clone(&exit),
        ));
        let reader = reader.abort_handle();

        Self {
            inner,
            peer,
            frames,
            incoming: tokio::sync::Mutex::new(incoming_rx),
            routes,
            live,
            exit,
            writer,
            reader,
            next_id: AtomicU32::new(role.next_id()),
        }
    }
}

impl<S: Session> Drop for NoiseSession<S> {
    /// Dropping a session cancels both frame pumps. The pumps own the inner stream halves, so
    /// cancelling them is what releases the inner connection; a keep-alive would otherwise outlive
    /// the session value. Queued frames not yet written are discarded, which is what dropping a
    /// session means: a caller that needs delivery awaits `wait_closed` first.
    fn drop(&mut self) {
        self.writer.abort();
        self.reader.abort();
    }
}

impl<S: Session> Session for NoiseSession<S> {
    type Security = Sealed;
    type Write = StreamWrite;
    type Read = StreamRead;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(StreamWrite, StreamRead), Error> {
        let Some(life) = StreamLife::acquire(&self.live) else {
            return Err(NoiseError::TooManyStreams.into_stream());
        };
        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        {
            let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
            routes.insert(
                id,
                Route {
                    tx,
                    life: Arc::downgrade(&life),
                },
            );
        }
        if self.frames.send(Outbound::Open(id)).await.is_err() {
            let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
            routes.remove(&id);
            return Err(Error::Closed);
        }
        Ok((
            StreamWrite::new(id, self.frames.clone(), Arc::clone(&life)),
            StreamRead::new(rx, life),
        ))
    }

    async fn accept_bi(&self) -> Result<(StreamWrite, StreamRead), Error> {
        let mut incoming = self.incoming.lock().await;
        let Inbound { id, rx, life } = incoming.recv().await.ok_or(Error::Closed)?;
        Ok((
            StreamWrite::new(id, self.frames.clone(), Arc::clone(&life)),
            StreamRead::new(rx, life),
        ))
    }

    async fn wait_closed(&self) {
        // The exit signal is the fallback for a session the frame pumps gave up on; the inner
        // session's own close is the authoritative end.
        tokio::select! {
            () = self.inner.wait_closed() => {}
            () = self.exit.wait() => {}
        }
    }

    fn conn_info(&self) -> ConnInfo {
        self.inner.conn_info()
    }
}

/// The writable half of a logical stream.
///
/// `shutdown` sends `FIN`; dropping the half without a shutdown sends `RESET`, so an abandoned
/// stream never leaves the peer's read parked. The reset is best effort: a full outbound queue can
/// drop it, and the session close then ends the stream.
pub struct StreamWrite {
    id: u32,
    frames: mpsc::Sender<Outbound>,
    life: Arc<StreamLife>,
    permit: Option<Reserve>,
    pending: Option<Outbound>,
    finished: bool,
}

/// A reserve future holding a cloned sender, so a full queue registers the write waker.
type Reserve = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<Outbound>, mpsc::error::SendError<()>>> + Send,
    >,
>;

impl StreamWrite {
    pub(crate) fn new(id: u32, frames: mpsc::Sender<Outbound>, life: Arc<StreamLife>) -> Self {
        Self {
            id,
            frames,
            life,
            permit: None,
            pending: None,
            finished: false,
        }
    }

    /// Queue one frame, waiting for queue capacity without holding the frame across polls.
    ///
    /// The frame replaces any frame left by a cancelled poll. `AsyncWrite` says a `Pending` write
    /// wrote nothing, so a later call with different bytes is owed those bytes; keeping the stale
    /// frame would silently substitute it for the caller's new one.
    fn poll_send(&mut self, cx: &mut Context<'_>, frame: Outbound) -> Poll<io::Result<()>> {
        if self.life.is_torn() {
            return Poll::Ready(Err(closed("session torn down")));
        }
        self.pending = Some(frame);
        loop {
            if let Some(reserve) = self.permit.as_mut() {
                match reserve.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        let Some(frame) = self.pending.take() else {
                            return Poll::Ready(Err(closed("stream frame lost")));
                        };
                        self.frames = permit.send(frame);
                        self.permit = None;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(closed("session closed"))),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let sender = self.frames.clone();
            self.permit = Some(Box::pin(sender.reserve_owned()));
        }
    }
}

impl AsyncWrite for StreamWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.finished {
            // Stricter than the `Ok(0)` convention: a write after this half's own shutdown is an
            // application bug, and the peer has already seen the `FIN`.
            return Poll::Ready(Err(closed("stream finished")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_CHUNK);
        let frame = Outbound::Data(this.id, buf[..n].to_vec());
        match this.poll_send(cx, frame) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        let frame = Outbound::Fin(this.id);
        match this.poll_send(cx, frame) {
            Poll::Ready(Ok(())) => {
                this.finished = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for StreamWrite {
    fn drop(&mut self) {
        // A torn session has already reset every live stream; a reset frame would be noise.
        if !self.finished && !self.life.is_torn() {
            let _ = self.frames.try_send(Outbound::Reset(self.id));
        }
    }
}

/// The readable half of a logical stream.
///
/// A `FIN` reads as a clean end; a `RESET` reads as [`io::ErrorKind::ConnectionReset`].
pub struct StreamRead {
    rx: mpsc::Receiver<Chunk>,
    life: Arc<StreamLife>,
    pending: Option<(Vec<u8>, usize)>,
}

impl StreamRead {
    pub(crate) fn new(rx: mpsc::Receiver<Chunk>, life: Arc<StreamLife>) -> Self {
        Self {
            rx,
            life,
            pending: None,
        }
    }
}

impl AsyncRead for StreamRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let Some((data, offset)) = this.pending.as_mut() {
            let n = (data.len() - *offset).min(buf.remaining());
            buf.put_slice(&data[*offset..*offset + n]);
            *offset += n;
            if *offset == data.len() {
                this.pending = None;
            }
            return Poll::Ready(Ok(()));
        }
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(Chunk::Data(data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.pending = Some((data, n));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Chunk::Reset)) => Poll::Ready(Err(torn())),
            // The queue ended. A clean end only if the whole session ended cleanly; a session
            // teardown marks the stream torn, so a truncated read never presents as EOF.
            Poll::Ready(None) => {
                if this.life.is_torn() {
                    Poll::Ready(Err(torn()))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Encrypt outbound frames until the session closes.
async fn write_loop<W: AsyncWrite + Unpin>(
    mut write: W,
    state: Arc<StdMutex<TransportState>>,
    mut frames: mpsc::Receiver<Outbound>,
    exit: Arc<Exit>,
) {
    let mut plaintext = Vec::with_capacity(MAX_FRAME_PLAINTEXT);
    let mut ciphertext = vec![0u8; MAX_FRAME_CIPHERTEXT];
    let mut wire = Vec::with_capacity(2 + MAX_FRAME_CIPHERTEXT);

    while let Some(frame) = frames.recv().await {
        frame.encode(&mut plaintext);
        if !write_frame(&mut write, &state, &plaintext, &mut ciphertext, &mut wire).await {
            break;
        }
    }
    let _ = write.flush().await;
    let _ = write.shutdown().await;
    exit.close();
}

/// Encrypt and write one plaintext frame; `false` means the channel or the inner stream is gone.
async fn write_frame<W: AsyncWrite + Unpin>(
    write: &mut W,
    state: &StdMutex<TransportState>,
    plaintext: &[u8],
    ciphertext: &mut [u8],
    wire: &mut Vec<u8>,
) -> bool {
    let len = {
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        state.write_message(plaintext, ciphertext)
    };
    let Ok(len) = len else {
        return false;
    };
    let Ok(len) = u16::try_from(len) else {
        return false;
    };
    wire.clear();
    wire.extend_from_slice(&len.to_be_bytes());
    wire.extend_from_slice(&ciphertext[..usize::from(len)]);
    if write.write_all(wire).await.is_err() {
        return false;
    }
    write.flush().await.is_ok()
}

/// Where an inbound frame goes: new streams to `incoming`, data to a stream's route, a dead
/// stream's `RESET` back out to the writer, and the concurrent open count for the cap.
struct Dispatch {
    routes: Arc<StdMutex<HashMap<u32, Route>>>,
    incoming: mpsc::Sender<Inbound>,
    frames: mpsc::Sender<Outbound>,
    live: Arc<AtomicU32>,
}

/// Decrypt inbound frames and route them to streams until the inner stream ends or a peer
/// violates the frame protocol.
async fn read_loop<R: AsyncRead + Unpin>(
    mut read: R,
    state: Arc<StdMutex<TransportState>>,
    dispatch: Dispatch,
    role: Role,
    abort_writer: AbortHandle,
    exit: Arc<Exit>,
) {
    let Dispatch {
        routes,
        incoming,
        frames,
        live,
    } = dispatch;
    let mut plaintext = vec![0u8; MAX_FRAME_PLAINTEXT];
    let mut fatal = false;

    loop {
        let message = match handshake::read_frame(&mut read, MAX_FRAME_CIPHERTEXT).await {
            Ok(message) => message,
            // The inner stream ended cleanly: the peer's session is gone.
            Err(NoiseError::Io(_)) => break,
            // A bad prefix is a protocol violation, not an end.
            Err(_) => {
                fatal = true;
                break;
            }
        };
        let len = {
            let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
            state.read_message(&message, &mut plaintext)
        };
        let len = match len {
            Ok(len) => len,
            Err(_) => {
                fatal = true;
                break;
            }
        };
        if len < FRAME_HEADER {
            fatal = true;
            break;
        }
        let kind = plaintext[0];
        let id = u32::from_be_bytes([plaintext[1], plaintext[2], plaintext[3], plaintext[4]]);
        let payload = &plaintext[FRAME_HEADER..len];

        match kind {
            KIND_OPEN => {
                if id % 2 != role.peer_parity() {
                    fatal = true;
                    break;
                }
                let Some(life) = StreamLife::acquire(&live) else {
                    fatal = true;
                    break;
                };
                let (tx, rx) = mpsc::channel(STREAM_QUEUE);
                let duplicate = {
                    let mut routes = routes.lock().unwrap_or_else(|p| p.into_inner());
                    routes
                        .insert(
                            id,
                            Route {
                                tx,
                                life: Arc::downgrade(&life),
                            },
                        )
                        .is_some()
                };
                if duplicate {
                    fatal = true;
                    break;
                }
                if incoming.send(Inbound { id, rx, life }).await.is_err() {
                    break;
                }
            }
            KIND_DATA => {
                let route = {
                    let routes = routes.lock().unwrap_or_else(|p| p.into_inner());
                    routes.get(&id).cloned()
                };
                let Some(route) = route else {
                    // Data for a stream that was never opened or is already closed.
                    fatal = true;
                    break;
                };
                if route.tx.send(Chunk::Data(payload.to_vec())).await.is_err() {
                    // The local reader is gone; tell the peer this stream is dead.
                    {
                        let mut routes = routes.lock().unwrap_or_else(|p| p.into_inner());
                        routes.remove(&id);
                    }
                    let _ = frames.try_send(Outbound::Reset(id));
                }
            }
            KIND_FIN => {
                // A close for an unknown stream is a duplicate teardown, not data; dropping it is
                // the fail-closed end (the stream can never deliver bytes again).
                let mut routes = routes.lock().unwrap_or_else(|p| p.into_inner());
                routes.remove(&id);
            }
            KIND_RESET => {
                let route = {
                    let mut routes = routes.lock().unwrap_or_else(|p| p.into_inner());
                    routes.remove(&id)
                };
                if let Some(route) = route {
                    let _ = route.tx.send(Chunk::Reset).await;
                }
            }
            _ => {
                fatal = true;
                break;
            }
        }
    }

    if fatal {
        abort_writer.abort();
    }
    // The session is over. Mark every live stream torn first (sticky, so a full queue cannot lose
    // it), then best-effort enqueue a reset and drop the routes; `accept_bi` sees `Closed` when the
    // reader task drops its `incoming` sender. This runs for a fatal frame and for a clean inner
    // end alike.
    {
        let mut routes = routes.lock().unwrap_or_else(|p| p.into_inner());
        for (_, route) in routes.drain() {
            if let Some(life) = route.life.upgrade() {
                life.tear();
            }
            let _ = route.tx.try_send(Chunk::Reset);
        }
    }
    exit.close();
}

/// A closed-stream I/O error carrying its reason.
fn closed(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, reason)
}

/// The error a reset stream or a torn session carries to its reads.
fn torn() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "stream torn down")
}
