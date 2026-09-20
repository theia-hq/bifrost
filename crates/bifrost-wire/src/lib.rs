//! The Bifrost wire: verified blob transfer over any byte stream.
//!
//! Pure bytes. A [`Transfer`] owns one bidirectional stream pair and is consumed to move a single
//! [`Blob`] across it, proving the bytes against their BLAKE3 root so a peer cannot lie about content
//! and a truncated transfer is rejected. It knows nothing about files, paths, filenames, iroh, QUIC,
//! or sockets: sources and sinks are any [`AsyncRead`]/[`AsyncWrite`] the caller supplies, and an
//! opaque `header` carries whatever application metadata the caller wants (a filename, a content
//! type), transmitted verbatim and never interpreted here.
//!
//! [`AsyncRead`]: tokio::io::AsyncRead
//! [`AsyncWrite`]: tokio::io::AsyncWrite

use tokio::io;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The largest app header this wire carries, in bytes, enforced at both ends.
///
/// A header names one blob, so the largest legitimate one is a name: POSIX bounds a whole filesystem
/// path at 4 KiB (`PATH_MAX`), and 64 KiB leaves sixteen times that for a header that carries more than
/// a name (a content type, a small manifest beside it). It is also the size of the streaming buffer the
/// receive path already holds, so the header is never the largest allocation in a transfer.
///
/// The bound exists because the length prefix is a `u32`: without it a receiver allocates whatever the
/// peer declares, up to 4 GiB, before reading one byte of the header it is sizing for. The cap is
/// checked against the prefix, so an oversized claim costs the receiver nothing.
pub const MAX_HEADER_LEN: u32 = 64 * 1024;

/// Frames a Bifrost blob transfer. Bumped when the header layout changes.
const MAGIC: [u8; 4] = *b"BFW1";
/// The receiver accepted and verified the blob.
const ACK_OK: u8 = 1;
/// The receiver rejected the blob (for example, an integrity failure).
const ACK_ERR: u8 = 0;
/// Streaming buffer size.
const CHUNK: usize = 64 * 1024;

/// A content-addressed blob descriptor: its BLAKE3 root and length. The root names the bytes, so
/// anyone can verify what they received against it and the source cannot lie about content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blob {
    root: [u8; 32],
    len: u64,
}

impl Blob {
    /// Hash a byte source into a descriptor, in one streaming pass.
    pub async fn hash<R>(source: &mut R) -> io::Result<Self>
    where
        R: io::AsyncRead + Unpin,
    {
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK];
        let mut len = 0u64;
        loop {
            let read = source.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
            len += read as u64;
        }
        Ok(Self {
            root: *hasher.finalize().as_bytes(),
            len,
        })
    }

    /// The BLAKE3 root that names this blob's bytes.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// The blob length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the blob is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A received blob: its opaque header and verified descriptor. The payload has already been written
/// to the caller's sink.
#[derive(Debug, Clone)]
pub struct Received {
    /// The opaque, app-defined header the sender attached.
    pub header: Vec<u8>,
    /// The verified descriptor of the received bytes.
    pub blob: Blob,
}

/// A verified blob transfer over one bidirectional byte-stream pair.
///
/// Owns the stream halves and is consumed by [`Transfer::send`] or [`Transfer::recv`]: one transfer,
/// one blob, one pair.
pub struct Transfer<W, R> {
    writer: W,
    reader: R,
}

impl<W, R> Transfer<W, R>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    /// Wrap a session's stream halves.
    pub fn new(writer: W, reader: R) -> Self {
        Self { writer, reader }
    }

    /// Send `blob`, streaming its bytes from `source`, with an opaque `header`; await the peer's ack.
    ///
    /// `blob` must describe `source` (produce it with [`Blob::hash`]); the receiver checks every byte
    /// against `blob`'s root.
    pub async fn send<Src>(mut self, header: &[u8], blob: &Blob, source: &mut Src) -> Result<()>
    where
        Src: io::AsyncRead + Unpin,
    {
        // Both ends hold the same bound, so an over-cap header fails here, named by the caller's own
        // error, rather than as a remote refusal partway through a frame the receiver was always going
        // to reject.
        let header_len = u32::try_from(header.len()).map_err(|_| Error::HeaderTooLong)?;
        if header_len > MAX_HEADER_LEN {
            return Err(Error::HeaderTooLong);
        }
        self.writer.write_all(&MAGIC).await?;
        self.writer.write_all(&header_len.to_be_bytes()).await?;
        self.writer.write_all(header).await?;
        self.writer.write_all(&blob.len.to_be_bytes()).await?;
        self.writer.write_all(&blob.root).await?;

        let copied = io::copy(source, &mut self.writer).await?;
        if copied != blob.len {
            return Err(Error::LengthMismatch);
        }
        // Finish the send half now: on QUIC this flushes every buffered byte and signals end of blob.
        // Waiting for the ack before finishing would deadlock (the receiver blocks on the last bytes
        // that finish is what delivers); the recv half stays open for the ack.
        self.writer.shutdown().await?;

        let mut ack = [0u8; 1];
        self.reader
            .read_exact(&mut ack)
            .await
            .map_err(|_| Error::Truncated)?;
        if ack[0] != ACK_OK {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    /// Receive a blob into `sink`, verifying every byte against the sender's root; then acknowledge.
    ///
    /// A hash mismatch or short read is an error and the receiver signals rejection.
    pub async fn recv<Sink>(mut self, sink: &mut Sink) -> Result<Received>
    where
        Sink: io::AsyncWrite + Unpin,
    {
        let mut magic = [0u8; 4];
        self.reader
            .read_exact(&mut magic)
            .await
            .map_err(|_| Error::Truncated)?;
        if magic != MAGIC {
            return Err(Error::BadMagic);
        }

        let header = self.read_framed().await?;
        let len = self.read_u64().await?;
        let mut root = [0u8; 32];
        self.reader
            .read_exact(&mut root)
            .await
            .map_err(|_| Error::Truncated)?;

        match self.verify_into(sink, len, &root).await {
            Ok(()) => {
                self.writer.write_all(&[ACK_OK]).await?;
                self.writer.shutdown().await?;
                Ok(Received {
                    header,
                    blob: Blob { root, len },
                })
            }
            Err(err) => {
                let _ = self.writer.write_all(&[ACK_ERR]).await;
                let _ = self.writer.shutdown().await;
                Err(err)
            }
        }
    }

    /// Stream exactly `len` bytes from the peer into `sink`, verifying them against `root`.
    async fn verify_into<Sink>(&mut self, sink: &mut Sink, len: u64, root: &[u8; 32]) -> Result<()>
    where
        Sink: io::AsyncWrite + Unpin,
    {
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; CHUNK];
        let mut remaining = len;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let read = self.reader.read(&mut buf[..want]).await?;
            if read == 0 {
                return Err(Error::Truncated);
            }
            hasher.update(&buf[..read]);
            sink.write_all(&buf[..read]).await?;
            remaining -= read as u64;
        }
        sink.flush().await?;
        if hasher.finalize().as_bytes() != root {
            return Err(Error::IntegrityFailed);
        }
        Ok(())
    }

    /// Read the one length-prefixed field the layout has, the app header, bounded by
    /// [`MAX_HEADER_LEN`].
    ///
    /// The cap is checked against the PREFIX, before the buffer exists: the peer's `u32` is a claim, and
    /// sizing a buffer to an unverified claim is what lets one frame commit 4 GiB of the host. An
    /// over-cap claim is [`Error::OversizedHeader`], never [`Error::Truncated`]: the frame is well
    /// formed and too big, which is a different answer than a stream that ended.
    async fn read_framed(&mut self) -> Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.reader
            .read_exact(&mut len)
            .await
            .map_err(|_| Error::Truncated)?;
        let len = u32::from_be_bytes(len);
        if len > MAX_HEADER_LEN {
            return Err(Error::OversizedHeader { len });
        }
        let mut bytes = vec![0u8; len as usize];
        self.reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| Error::Truncated)?;
        Ok(bytes)
    }

    async fn read_u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| Error::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }
}

/// Why a blob transfer failed.
///
/// Non-exhaustive: hardening this wire adds classes, and [`OversizedHeader`](Self::OversizedHeader) is
/// one. Match the classes you act on and keep a catch-all for the rest, so a class a newer peer can
/// earn never inherits whichever arm happened to be written first.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An underlying read or write failed.
    #[error("io")]
    Io(#[from] std::io::Error),
    /// The stream did not begin with the expected frame magic.
    #[error("bad frame magic")]
    BadMagic,
    /// The app header handed to [`Transfer::send`] was over [`MAX_HEADER_LEN`].
    #[error("header too long")]
    HeaderTooLong,
    /// The peer declared a header over [`MAX_HEADER_LEN`]. Refused from the length prefix alone, so no
    /// buffer is ever sized to the claim.
    #[error("peer declared a {len} byte header, over the {MAX_HEADER_LEN} byte cap")]
    OversizedHeader {
        /// The header length the peer declared, in bytes.
        len: u32,
    },
    /// The source produced a different number of bytes than the blob declared.
    #[error("source length did not match the blob length")]
    LengthMismatch,
    /// The received bytes did not match their hash.
    #[error("integrity check failed: content did not match its hash")]
    IntegrityFailed,
    /// The peer closed the stream before the transfer completed.
    #[error("transfer truncated")]
    Truncated,
    /// The peer rejected the transfer.
    #[error("peer rejected the transfer")]
    Rejected,
}

type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod lib_tests;
