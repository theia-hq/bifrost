use tokio::io;

use super::{Blob, Error, MAX_HEADER_LEN, Transfer};

/// The four magic bytes a well-formed frame opens with, spelled out rather than imported, so a test
/// cannot agree with the codec by sharing its constant.
const MAGIC: [u8; 4] = *b"BFW1";

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

/// Splitting the magic moved no byte: a frame still opens with the same four octets it always did.
/// The split is a change to how the receiver READS the magic, never to what the sender writes, so a
/// shipped peer on either side is unaffected. Write the version before the identity, or widen either
/// half, and this goes red.
#[tokio::test]
async fn a_frame_still_opens_with_the_same_four_octets() {
    let payload = b"payload".to_vec();
    let blob = Blob::hash(&mut payload.as_slice())
        .await
        .expect("the blob hashes");

    let mut written = Vec::new();
    Transfer::new(&mut written, b"".as_slice())
        .send(b"header", &blob, &mut payload.as_slice())
        .await
        .expect_err("there is no peer to ack, and the frame is written before the read");

    assert_eq!(&written[..4], &MAGIC);
}

/// One well-formed frame prefix with the byte at `at` replaced. The two tests below differ only in
/// WHICH half of the magic they corrupt, because that single difference is the whole claim.
fn magic_with(at: usize, byte: u8) -> Vec<u8> {
    let mut frame = header_claim(0);
    frame[at] = byte;
    frame
}

/// A stream whose IDENTITY is not ours is not a bifrost-wire stream, and that is all it is. Make the
/// version arm fire for a foreign identity too and the first assertion goes red.
#[tokio::test]
async fn a_foreign_identity_is_not_a_version_mismatch() {
    let mut sink = Vec::new();
    // `XFW1`: one byte of the identity changed, and nothing else.
    let error = Transfer::new(Vec::new(), magic_with(0, b'X').as_slice())
        .recv(&mut sink)
        .await
        .expect_err("a foreign identity is not a bifrost-wire stream");

    assert!(
        !matches!(error, Error::VersionMismatch { .. }),
        "whatever wrote XFW1 is not a bifrost-wire peer on another build: {error}"
    );
    assert!(matches!(error, Error::Foreign), "{error}");
}

/// The version half of the magic is PARSED, so a bifrost-wire peer on another build is a
/// distinguishable condition rather than a foreign stream. Revert the parse to a four-byte
/// comparison and this goes red at the first assertion.
///
/// The distinction is worth nothing on the wire here (the sender is mid-body and not reading, so
/// there is nobody to tell) and everything in the message, which is why the last two assertions pin
/// both version tags: that string is the whole answer this wire gets to give.
#[tokio::test]
async fn a_version_mismatch_is_not_a_foreign_stream() {
    let mut sink = Vec::new();
    // `BFW2`: one byte of the version changed, and nothing else.
    let error = Transfer::new(Vec::new(), magic_with(3, b'2').as_slice())
        .recv(&mut sink)
        .await
        .expect_err("BFW2 is not this build's grammar");

    assert!(
        !matches!(error, Error::Foreign),
        "a bifrost-wire peer on another build is not a foreign protocol: {error}"
    );
    assert!(matches!(error, Error::VersionMismatch { .. }), "{error}");
    let message = error.to_string();
    assert!(message.contains("BFW2"), "{message}");
    assert!(message.contains("BFW1"), "{message}");
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
