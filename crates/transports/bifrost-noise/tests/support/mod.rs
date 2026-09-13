//! Test support: a single-stream, byte-carrying inner transport plus two hostile peers.
//!
//! `Wire` mirrors the shape of the smallest real backend (one inner stream per session and no
//! crypto of its own) so the wrapper's mux is exercised on the least generous inner, and it
//! records every byte each side writes so a test can assert what a peer did or did not send.

#![allow(dead_code)]

use core::net::SocketAddr;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use core::task::{Context, Poll};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use bifrost_core::{Addr, BoxError, Error, NodeId};
use bifrost_transport::{Announced, Session, Transport};
use ed25519_dalek::{Signer as _, SigningKey};
use snow::Builder;
use snow::params::NoiseParams;
use tokio::io::{self as tokio_io, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

/// Buffer for each in-process duplex, matching the other backends' stream buffer.
const CAP: usize = 64 * 1024;

/// Source of unique synthetic ports, one per bound endpoint.
static PORTS: AtomicU16 = AtomicU16::new(1);

/// Bound endpoints by synthetic port.
static REGISTRY: LazyLock<StdMutex<HashMap<u16, Endpoint>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

struct Endpoint {
    sender: mpsc::UnboundedSender<WireSession>,
    node: NodeId,
    lie: Option<NodeId>,
    writes: Arc<StdMutex<Vec<u8>>>,
}

type Stream = (
    TapWriter<tokio_io::WriteHalf<tokio_io::DuplexStream>>,
    tokio_io::ReadHalf<tokio_io::DuplexStream>,
);

/// An in-process, single-stream transport with real ed25519 identities.
pub struct Wire {
    node: NodeId,
    lie: Option<NodeId>,
    port: u16,
    inbound: AsyncMutex<mpsc::UnboundedReceiver<WireSession>>,
    writes: Arc<StdMutex<Vec<u8>>>,
}

impl Wire {
    /// Bind an endpoint under the identity `seed` derives.
    pub fn bind(seed: [u8; NodeId::KEY_LEN]) -> Self {
        Self::bind_lying(seed, None)
    }

    /// Bind an endpoint whose sessions report `peer` regardless of who dialed.
    pub fn bind_lying(seed: [u8; NodeId::KEY_LEN], lie: Option<NodeId>) -> Self {
        let node = NodeId::from_ed25519_secret(&seed);
        let port = PORTS.fetch_add(1, Ordering::Relaxed);
        let (sender, inbound) = mpsc::unbounded_channel();
        let writes = Arc::new(StdMutex::new(Vec::new()));
        REGISTRY.lock().unwrap_or_else(|p| p.into_inner()).insert(
            port,
            Endpoint {
                sender,
                node,
                lie,
                writes: Arc::clone(&writes),
            },
        );
        Self {
            node,
            lie,
            port,
            inbound: AsyncMutex::new(inbound),
            writes,
        }
    }

    /// Every byte this transport's sessions have written.
    pub fn writes(&self) -> Arc<StdMutex<Vec<u8>>> {
        Arc::clone(&self.writes)
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        REGISTRY
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.port);
    }
}

impl Transport for Wire {
    type Security = Announced;
    type Session = WireSession;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        Addr {
            node: self.node,
            hints: vec![SocketAddr::from(([127, 0, 0, 1], self.port))],
        }
    }

    async fn connect(&self, addr: Addr) -> Result<WireSession, Error> {
        let port = addr
            .hints
            .first()
            .map(SocketAddr::port)
            .ok_or_else(|| Error::Connect(Box::new(io::Error::other("wire needs a hint"))))?;
        let (sender, endpoint_node, endpoint_lie, endpoint_writes) = {
            let registry = REGISTRY.lock().unwrap_or_else(|p| p.into_inner());
            let endpoint = registry
                .get(&port)
                .ok_or_else(|| Error::Connect(Box::new(io::Error::other("no endpoint"))))?;
            (
                endpoint.sender.clone(),
                endpoint.node,
                endpoint.lie,
                Arc::clone(&endpoint.writes),
            )
        };

        let (near, far) = tokio_io::duplex(CAP);
        let (near_read, near_write) = tokio_io::split(near);
        let (far_read, far_write) = tokio_io::split(far);
        let end = Arc::new(SessionEnd::default());

        let dialer = WireSession {
            peer: endpoint_lie.unwrap_or(endpoint_node),
            first: StdMutex::new(Some((
                TapWriter::new(near_write, Arc::clone(&self.writes)),
                near_read,
            ))),
            opener: true,
            ended: Arc::clone(&end),
        };
        let accepter = WireSession {
            peer: self.lie.unwrap_or(self.node),
            first: StdMutex::new(Some((TapWriter::new(far_write, endpoint_writes), far_read))),
            opener: false,
            ended: end,
        };
        sender
            .send(accepter)
            .map_err(|_| Error::Connect(Box::new(io::Error::other("endpoint gone"))))?;
        Ok(dialer)
    }

    async fn accept(&self) -> Result<WireSession, Error> {
        let mut inbound = self.inbound.lock().await;
        inbound.recv().await.ok_or(Error::Closed)
    }

    async fn close(&self) {}
}

/// A single-stream in-process session.
pub struct WireSession {
    peer: NodeId,
    first: StdMutex<Option<Stream>>,
    opener: bool,
    ended: Arc<SessionEnd>,
}

impl WireSession {
    fn take(&self) -> Option<Stream> {
        self.first.lock().unwrap_or_else(|p| p.into_inner()).take()
    }
}

impl Session for WireSession {
    type Security = Announced;
    type Write = TapWriter<tokio_io::WriteHalf<tokio_io::DuplexStream>>;
    type Read = tokio_io::ReadHalf<tokio_io::DuplexStream>;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        if !self.opener {
            return Err(Error::Closed);
        }
        self.take().ok_or(Error::Closed)
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), Error> {
        if self.opener {
            return Err(Error::Closed);
        }
        self.take().ok_or(Error::Closed)
    }

    async fn wait_closed(&self) {
        if self.ended.closed.load(Ordering::Acquire) {
            return;
        }
        // `notify_one` stores a permit, so a close that lands before the await is still observed.
        let notified = self.ended.notify.notified();
        if self.ended.closed.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

/// The close signal shared by the two ends of one connection.
#[derive(Default)]
struct SessionEnd {
    closed: AtomicBool,
    notify: Notify,
}

impl Drop for WireSession {
    fn drop(&mut self) {
        self.ended.closed.store(true, Ordering::Release);
        self.ended.notify.notify_one();
    }
}

/// An `AsyncWrite` that records every accepted byte before forwarding it.
pub struct TapWriter<W> {
    inner: W,
    log: Arc<StdMutex<Vec<u8>>>,
}

impl<W> TapWriter<W> {
    fn new(inner: W, log: Arc<StdMutex<Vec<u8>>>) -> Self {
        Self { inner, log }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for TapWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = std::task::ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(&buf[..written]);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A session handed back by the hostile peers. It holds the inner connection and its single
/// stream so the peer can keep the connection open while the responder processes what it sent.
pub struct Forged {
    peer: NodeId,
    _session: Option<WireSession>,
    _stream: Option<Stream>,
}

impl Forged {
    fn hold(peer: NodeId, session: WireSession, stream: Stream) -> Self {
        Self {
            peer,
            _session: Some(session),
            _stream: Some(stream),
        }
    }
}

impl Session for Forged {
    type Security = Announced;
    type Write = tokio_io::Sink;
    type Read = tokio_io::Empty;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(tokio_io::Sink, tokio_io::Empty), Error> {
        Ok((tokio_io::sink(), tokio_io::empty()))
    }

    async fn accept_bi(&self) -> Result<(tokio_io::Sink, tokio_io::Empty), Error> {
        Ok((tokio_io::sink(), tokio_io::empty()))
    }

    async fn wait_closed(&self) {}
}

/// A wire-speaking impostor: it runs the real protocol with its own key but claims `claim`.
pub struct Forger {
    inner: Wire,
    identity: SigningKey,
    claim: NodeId,
}

impl Forger {
    /// Dial with `seed`'s identity while advertising `claim` in the payload.
    pub fn new(seed: [u8; NodeId::KEY_LEN], claim: NodeId) -> Self {
        Self {
            inner: Wire::bind(seed),
            identity: SigningKey::from_bytes(&seed),
            claim,
        }
    }
}

impl Transport for Forger {
    type Security = Announced;
    type Session = Forged;

    fn node_id(&self) -> NodeId {
        NodeId::from_ed25519_secret(&[0u8; NodeId::KEY_LEN])
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    async fn connect(&self, addr: Addr) -> Result<Forged, Error> {
        let session = self.inner.connect(addr).await?;
        let (mut write, mut read) = session.open_bi().await?;
        let mut dialog = exchange_two_messages(&mut write, &mut read)
            .await
            .map_err(Error::Connect)?;
        let payload = finish_payload(&self.identity, self.claim, &dialog.h2, &dialog.own_static);
        send_third(&mut write, &mut dialog.state, &payload)
            .await
            .map_err(Error::Connect)?;
        Ok(Forged::hold(self.claim, session, (write, read)))
    }

    async fn accept(&self) -> Result<Forged, Error> {
        Err(Error::Closed)
    }

    async fn close(&self) {}
}

/// A dishonest post-handshake peer: it completes the handshake honestly, then violates the frame
/// protocol in one of the ways the reader must treat as fatal.
#[derive(Clone, Copy)]
pub enum Sabotage {
    /// `DATA` for a stream that was never opened.
    UnknownData,
    /// A length prefix past the frame cap, with no body.
    OversizedPrefix,
    /// One ciphertext sent twice.
    ReplayedFrame,
    /// Nine 4088-byte `DATA` frames (past the 8-chunk stream queue), then a fatal frame.
    SaturateThenFatal,
}

/// A peer that blows up the frame layer after an honest handshake.
pub struct Saboteur {
    inner: Wire,
    identity: SigningKey,
    node: NodeId,
    mode: Sabotage,
}

impl Saboteur {
    /// Dial with `seed`'s identity and sabotage after the handshake.
    pub fn new(seed: [u8; NodeId::KEY_LEN], mode: Sabotage) -> Self {
        Self {
            inner: Wire::bind(seed),
            identity: SigningKey::from_bytes(&seed),
            node: NodeId::from_ed25519_secret(&seed),
            mode,
        }
    }
}

impl Transport for Saboteur {
    type Security = Announced;
    type Session = Forged;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    async fn connect(&self, addr: Addr) -> Result<Forged, Error> {
        let session = self.inner.connect(addr).await?;
        let (mut write, mut read) = session.open_bi().await?;
        let mut dialog = exchange_two_messages(&mut write, &mut read)
            .await
            .map_err(Error::Connect)?;
        let payload = finish_payload(&self.identity, self.node, &dialog.h2, &dialog.own_static);
        send_third(&mut write, &mut dialog.state, &payload)
            .await
            .map_err(Error::Connect)?;
        let mut state = dialog
            .state
            .into_transport_mode()
            .map_err(|err| Error::Connect(Box::new(err)))?;

        // One honest stream, so the responder has a pending read to strand.
        let open = frame(bifrost_noise::wire::FRAME_OPEN, 0, &[]);
        seal_and_send(&mut write, &mut state, &open)
            .await
            .map_err(Error::Connect)?;

        match self.mode {
            Sabotage::UnknownData => {
                // Stream 2 was never opened by either side.
                let bad = frame(bifrost_noise::wire::FRAME_DATA, 2, &[]);
                seal_and_send(&mut write, &mut state, &bad)
                    .await
                    .map_err(Error::Connect)?;
            }
            Sabotage::OversizedPrefix => {
                // One past the ratified 16400-byte ciphertext cap, with no body.
                write
                    .write_all(&16401u16.to_be_bytes())
                    .await
                    .map_err(|err| Error::Connect(Box::new(err)))?;
            }
            Sabotage::ReplayedFrame => {
                let sealed = seal(
                    &mut state,
                    &frame(bifrost_noise::wire::FRAME_DATA, 0, b"payload"),
                )
                .map_err(Error::Connect)?;
                write
                    .write_all(&sealed)
                    .await
                    .map_err(|err| Error::Connect(Box::new(err)))?;
                write
                    .write_all(&sealed)
                    .await
                    .map_err(|err| Error::Connect(Box::new(err)))?;
            }
            Sabotage::SaturateThenFatal => {
                for _ in 0..9 {
                    let data = frame(bifrost_noise::wire::FRAME_DATA, 0, &[0x5a; 4088]);
                    seal_and_send(&mut write, &mut state, &data)
                        .await
                        .map_err(Error::Connect)?;
                }
                let bad = frame(bifrost_noise::wire::FRAME_DATA, 2, &[]);
                seal_and_send(&mut write, &mut state, &bad)
                    .await
                    .map_err(Error::Connect)?;
            }
        }
        write
            .flush()
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        Ok(Forged::hold(self.node, session, (write, read)))
    }

    async fn accept(&self) -> Result<Forged, Error> {
        Err(Error::Closed)
    }

    async fn close(&self) {}
}

/// A peer that does not speak the wrapper at all: it opens a stream and writes a wrong tag.
pub struct BarePeer {
    inner: Wire,
}

impl BarePeer {
    /// Bind a bare peer under `seed`'s identity.
    pub fn new(seed: [u8; NodeId::KEY_LEN]) -> Self {
        Self {
            inner: Wire::bind(seed),
        }
    }
}

impl Transport for BarePeer {
    type Security = Announced;
    type Session = Forged;

    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    async fn connect(&self, addr: Addr) -> Result<Forged, Error> {
        let session = self.inner.connect(addr).await?;
        let (mut write, read) = session.open_bi().await?;
        // Same length as the v0 tag, wrong bytes.
        write
            .write_all(b"bifrost-noise/x\n")
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        write
            .flush()
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        Ok(Forged::hold(self.inner.node_id(), session, (write, read)))
    }

    async fn accept(&self) -> Result<Forged, Error> {
        Err(Error::Closed)
    }

    async fn close(&self) {}
}

/// A wire splicer: it runs a fresh handshake through message two, then writes a recorded third
/// message from another session instead of its own.
pub struct Splicer {
    inner: Wire,
    node: NodeId,
    third: Vec<u8>,
}

impl Splicer {
    /// Splice `third` (a recorded `[len][ciphertext]` frame) into a fresh handshake.
    pub fn new(seed: [u8; NodeId::KEY_LEN], third: Vec<u8>) -> Self {
        Self {
            inner: Wire::bind(seed),
            node: NodeId::from_ed25519_secret(&seed),
            third,
        }
    }
}

impl Transport for Splicer {
    type Security = Announced;
    type Session = Forged;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    async fn connect(&self, addr: Addr) -> Result<Forged, Error> {
        let session = self.inner.connect(addr).await?;
        let (mut write, mut read) = session.open_bi().await?;
        let _fresh = exchange_two_messages(&mut write, &mut read)
            .await
            .map_err(Error::Connect)?;
        write
            .write_all(&self.third)
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        write
            .flush()
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        Ok(Forged::hold(self.node, session, (write, read)))
    }

    async fn accept(&self) -> Result<Forged, Error> {
        Err(Error::Closed)
    }

    async fn close(&self) {}
}

/// A wire replayer: it writes a recorded flight verbatim and holds the stream open.
pub struct Replayer {
    inner: Wire,
    flight: Vec<u8>,
}

impl Replayer {
    /// Replay `flight` over a fresh inner session.
    pub fn new(seed: [u8; NodeId::KEY_LEN], flight: Vec<u8>) -> Self {
        Self {
            inner: Wire::bind(seed),
            flight,
        }
    }
}

impl Transport for Replayer {
    type Security = Announced;
    type Session = Forged;

    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    async fn connect(&self, addr: Addr) -> Result<Forged, Error> {
        let session = self.inner.connect(addr).await?;
        let (mut write, read) = session.open_bi().await?;
        write
            .write_all(&self.flight)
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        write
            .flush()
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        Ok(Forged::hold(self.inner.node_id(), session, (write, read)))
    }

    async fn accept(&self) -> Result<Forged, Error> {
        Err(Error::Closed)
    }

    async fn close(&self) {}
}

/// A dialog through message two: tag exchange, message one, message two decrypted.
struct Dialog {
    state: snow::HandshakeState,
    h2: Vec<u8>,
    own_static: Vec<u8>,
}

/// Run the initiator through the first two XX messages, without verifying the responder.
async fn exchange_two_messages<W, R>(write: &mut W, read: &mut R) -> Result<Dialog, BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    write.write_all(bifrost_noise::wire::TAG).await?;
    write.flush().await?;
    let mut tag = [0u8; bifrost_noise::wire::TAG.len()];
    read.read_exact(&mut tag).await?;

    let params: NoiseParams = bifrost_noise::wire::PATTERN
        .parse()
        .map_err(|_| io::Error::other("pattern"))?;
    let builder = Builder::new(params).prologue(bifrost_noise::wire::PROLOGUE)?;
    let keypair = builder.generate_keypair()?;
    let mut state = builder
        .local_private_key(&keypair.private)?
        .build_initiator()?;

    let mut message = vec![0u8; 4096];
    let n = state.write_message(&[], &mut message)?;
    send_outer(write, &message[..n]).await?;

    let reply = read_outer(read, 4096).await?;
    let mut payload = vec![0u8; 4096];
    state.read_message(&reply, &mut payload)?;
    let h2 = state.get_handshake_hash().to_vec();
    Ok(Dialog {
        state,
        h2,
        own_static: keypair.public,
    })
}

/// Sign the initiator's transcript with `claim` as the advertised identity.
fn finish_payload(identity: &SigningKey, claim: NodeId, h2: &[u8], own_static: &[u8]) -> Vec<u8> {
    let mut signed = Vec::new();
    signed.extend_from_slice(bifrost_noise::wire::CTX_INITIATOR);
    signed.extend_from_slice(h2);
    signed.extend_from_slice(own_static);
    let signature = identity.sign(&signed);

    let mut payload = Vec::with_capacity(bifrost_noise::wire::PAYLOAD_LEN);
    payload.extend_from_slice(claim.key());
    payload.extend_from_slice(&signature.to_bytes());
    payload
}

/// Write the third XX message with `payload`.
async fn send_third<W: AsyncWrite + Unpin>(
    write: &mut W,
    state: &mut snow::HandshakeState,
    payload: &[u8],
) -> Result<(), BoxError> {
    let mut message = vec![0u8; 4096];
    let n = state.write_message(payload, &mut message)?;
    send_outer(write, &message[..n]).await?;
    Ok(())
}

/// `kind || id_be || payload`, the frozen frame layout.
fn frame(kind: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(kind);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Seal one plaintext frame into `[len][ciphertext]`.
fn seal(state: &mut snow::TransportState, plaintext: &[u8]) -> Result<Vec<u8>, BoxError> {
    let mut ciphertext = vec![0u8; plaintext.len() + 32];
    let n = state.write_message(plaintext, &mut ciphertext)?;
    let len = u16::try_from(n).map_err(|_| io::Error::other("message too long"))?;
    let mut wire = Vec::with_capacity(2 + n);
    wire.extend_from_slice(&len.to_be_bytes());
    wire.extend_from_slice(&ciphertext[..n]);
    Ok(wire)
}

/// Seal and write one plaintext frame.
async fn seal_and_send<W: AsyncWrite + Unpin>(
    write: &mut W,
    state: &mut snow::TransportState,
    plaintext: &[u8],
) -> Result<(), BoxError> {
    let wire = seal(state, plaintext)?;
    write.write_all(&wire).await?;
    write.flush().await?;
    Ok(())
}

async fn send_outer<W: AsyncWrite + Unpin>(write: &mut W, message: &[u8]) -> Result<(), BoxError> {
    let len = u16::try_from(message.len()).map_err(|_| io::Error::other("message too long"))?;
    write.write_all(&len.to_be_bytes()).await?;
    write.write_all(message).await?;
    write.flush().await?;
    Ok(())
}

async fn read_outer<R: AsyncRead + Unpin>(read: &mut R, max: usize) -> Result<Vec<u8>, BoxError> {
    let mut len = [0u8; 2];
    read.read_exact(&mut len).await?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > max {
        return Err(io::Error::other("message too long").into());
    }
    let mut message = vec![0u8; len];
    read.read_exact(&mut message).await?;
    Ok(message)
}
