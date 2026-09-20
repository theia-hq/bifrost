use tokio::io;

use super::{Blob, Error, MAGIC, MAX_HEADER_LEN, Transfer};

/// A frame prefix: the magic, then a header length, and nothing after it. A receiver that sized a
/// buffer to `header_len` before checking it would find no body and answer `Truncated`; one that
/// checks the prefix answers from these nine bytes alone.
fn header_claim(header_len: u32) -> Vec<u8> {
    let mut frame = MAGIC.to_vec();
    frame.extend_from_slice(&header_len.to_be_bytes());
    frame
}

/// THE guard: a hostile `u32` is refused from the length prefix, before any buffer is sized to it.
///
/// Delete the cap in `read_framed` and this goes red: the receiver allocates 4 GiB, finds no body, and
/// answers `Truncated`. The negative assertion is first so the removal is named as the removal rather
/// than as a mismatched variant.
///
/// What this CANNOT observe is the allocation itself. Watching that directly needs a counting
/// `#[global_allocator]`, which needs `unsafe impl GlobalAlloc`, and this workspace denies
/// `unsafe_code` with a two-file allowlist. So the fixture proves the next best thing and proves it
/// exactly: the refusal is derived from the prefix, because there is nothing else on the stream to
/// derive it from.
#[tokio::test]
async fn an_over_cap_header_length_is_refused_from_the_prefix_alone() {
    let mut sink = Vec::new();
    let error = Transfer::new(Vec::new(), header_claim(u32::MAX).as_slice())
        .recv(&mut sink)
        .await
        .expect_err("a 4 GiB header claim is refused");

    assert!(
        !matches!(error, Error::Truncated),
        "the cap is gone: the receiver sized a buffer to the claim and then ran out of stream"
    );
    assert!(
        matches!(error, Error::OversizedHeader { len } if len == u32::MAX),
        "an oversized frame is its own class, not a truncated one: {error}"
    );
}

/// The cap is a ceiling, not a neighbourhood: one byte over is refused.
#[tokio::test]
async fn a_header_one_byte_over_the_cap_is_refused() {
    let mut sink = Vec::new();
    let error = Transfer::new(Vec::new(), header_claim(MAX_HEADER_LEN + 1).as_slice())
        .recv(&mut sink)
        .await
        .expect_err("one byte over the cap is refused");

    assert!(
        matches!(error, Error::OversizedHeader { len } if len == MAX_HEADER_LEN + 1),
        "{error}"
    );
}

/// The other side of the ceiling: a header exactly at the cap is legal and arrives whole, so the
/// bound refuses only what is over it.
#[tokio::test]
async fn a_header_at_the_cap_round_trips() {
    let header = vec![b'h'; MAX_HEADER_LEN as usize];
    let payload = b"payload".to_vec();

    let (sender, receiver) = io::duplex(64 * 1024);
    let (sender_read, sender_write) = io::split(sender);
    let (receiver_read, receiver_write) = io::split(receiver);

    let sent = header.clone();
    let sending = tokio::spawn(async move {
        let mut source = payload.as_slice();
        let blob = Blob::hash(&mut source).await.expect("the blob hashes");
        let mut source = payload.as_slice();
        Transfer::new(sender_write, sender_read)
            .send(&sent, &blob, &mut source)
            .await
    });

    let mut sink = Vec::new();
    let received = Transfer::new(receiver_write, receiver_read)
        .recv(&mut sink)
        .await
        .expect("a header at the cap is accepted");

    sending
        .await
        .expect("the sender task completes")
        .expect("the sender is acked");
    assert_eq!(received.header, header);
    assert_eq!(sink, b"payload");
}

/// A sender refuses its own over-cap header, and refuses it before a byte reaches the wire: the two
/// ends hold one bound, so an over-long header is a local error, never a half-written frame the peer
/// has to reject.
#[tokio::test]
async fn a_sender_refuses_its_own_over_cap_header() {
    let header = vec![b'h'; MAX_HEADER_LEN as usize + 1];
    let payload = b"payload".to_vec();
    let mut source = payload.as_slice();
    let blob = Blob::hash(&mut source).await.expect("the blob hashes");

    let mut written = Vec::new();
    let error = Transfer::new(&mut written, b"".as_slice())
        .send(&header, &blob, &mut payload.as_slice())
        .await
        .expect_err("an over-cap header is refused locally");

    assert!(matches!(error, Error::HeaderTooLong), "{error}");
    assert!(written.is_empty(), "nothing reaches the wire");
}
