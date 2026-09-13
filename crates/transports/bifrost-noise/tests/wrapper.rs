//! The sealed wrapper against a byte-carrying inner, honest and hostile.
//!
//! The Wire inner moves real bytes over an in-process duplex and has no crypto, so these cases
//! isolate the wrapper: the shared conformance suite runs over it, the outer handshake binds the
//! peer while the inner announces a different identity, a fabricated signer and a replayed flight
//! yield no session, and a failed dial never writes the third flight.

mod support;

use core::time::Duration;
use std::io;

use bifrost::{Addr, Error, Node, NodeId, StaticDiscovery, Transport};
use bifrost_conformance::{
    close_drains, identity_binding, reach_roundtrip, unknown_conn_info, wrong_key_rejected,
};
use bifrost_noise::{Noise, NoiseError, wire};
use bifrost_transport::Session;
use support::{BarePeer, Forger, Replayer, Sabotage, Saboteur, Splicer, Wire};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The recorded third frame of a dialer flight: `tag || frame(msg1) || frame(msg3)`.
fn third_frame(flight: &[u8]) -> Option<&[u8]> {
    let rest = flight.strip_prefix(wire::TAG)?;
    let first = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
    let third = rest.get(2 + first..)?;
    if third.len() < 2 {
        return None;
    }
    Some(third)
}

fn seed(byte: u8) -> [u8; NodeId::KEY_LEN] {
    [byte; NodeId::KEY_LEN]
}

fn node(byte: u8) -> NodeId {
    NodeId::from_ed25519_secret(&seed(byte))
}

// A test helper, not a `#[test]` fn, so `allow-expect-in-tests` does not reach the expect inside it.
#[allow(clippy::expect_used)]
fn sealed(byte: u8) -> Noise<Wire> {
    Noise::new(Wire::bind(seed(byte)), seed(byte)).expect("wrap the inner")
}

fn dial_addr(receiver: &Noise<Wire>) -> Addr {
    Addr {
        node: receiver.node_id(),
        hints: receiver.local_addr().hints,
    }
}

/// The wrapper passes the blob round-trip over a byte-carrying inner.
#[tokio::test]
async fn wrapper_reach_roundtrip() {
    let receiver = sealed(2);
    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    let sender = Node::new(sealed(3), discovery);
    reach_roundtrip(sender, receiver).await;
}

/// The wrapper honors close/drain: a sender that writes, finishes, and closes delivers every byte.
#[tokio::test]
async fn wrapper_close_drains() {
    let receiver = sealed(4);
    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    let sender = Node::new(sealed(5), discovery);
    close_drains(sender, receiver).await;
}

/// Both ends attribute the identity the wrapper handshake proved.
#[tokio::test]
async fn wrapper_identity_binding() {
    identity_binding(sealed(6), sealed(7)).await;
}

/// A dial to a fabricated identity at the receiver's real address yields no session.
///
/// No acceptor runs on the receiver's side, so the dial fails at the wrapper's handshake deadline;
/// the paused clock advances to it without spending the wall time.
#[tokio::test(start_paused = true)]
async fn wrapper_wrong_key_rejected() {
    wrong_key_rejected(sealed(8), sealed(9), node(10)).await;
}

/// The wrapper reports the inner's `conn_info`; an uninstrumented inner inherits `Unknown`.
#[tokio::test]
async fn wrapper_unknown_conn_info() {
    let receiver = sealed(11);
    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    let sender = Node::new(sealed(12), discovery);
    unknown_conn_info(sender, receiver).await;
}

/// The W1 gate. The inner session announces a member's identity; the wrapper must attribute the
/// identity its own handshake proved, never the announcement, and never a value carried before the
/// signature check.
#[tokio::test]
async fn accept_binds_peer_to_handshake_not_announcement() {
    let victim = node(13);
    let receiver =
        Noise::new(Wire::bind_lying(seed(14), Some(victim)), seed(14)).expect("receiver");
    let dialer = sealed(15);
    let (accepted, dialed) = tokio::join!(receiver.accept(), dialer.connect(dial_addr(&receiver)));

    let accepted = accepted.expect("the responder accepts the honest dial");
    let dialed = dialed.expect("the dialer completes");
    assert_eq!(dialed.peer(), node(14));
    assert_eq!(
        accepted.peer(),
        node(15),
        "the acceptor attributes the handshake peer"
    );
    assert_ne!(
        accepted.peer(),
        victim,
        "the inner announcement is not an authority"
    );
}

/// The dialer pins the responder to the dialed identity, and writes no third flight when the pin
/// fails, so a hostile responder that cannot sign as the dialed key learns only the ephemeral.
#[tokio::test]
async fn dial_pins_responder_to_dialed_node() {
    let receiver = sealed(16);
    let dialer_inner = Wire::bind(seed(17));
    let written = dialer_inner.writes();
    let dialer = Noise::new(dialer_inner, seed(17)).expect("dialer");
    let victim = node(18);
    let addr = Addr {
        node: victim,
        hints: receiver.local_addr().hints,
    };

    let (accepted, dialed) = tokio::join!(receiver.accept(), dialer.connect(addr));
    assert!(dialed.is_err(), "the dialer pins the responder");
    assert!(accepted.is_err(), "no session speaks for the victim");

    let written = written.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(written.starts_with(wire::TAG), "the dial wrote its tag");
    let rest = &written[wire::TAG.len()..];
    assert_eq!(
        u16::from_be_bytes([rest[0], rest[1]]) as usize,
        32,
        "message one is one ephemeral"
    );
    assert_eq!(
        rest.len(),
        2 + 32,
        "verify-before-send: the dialer wrote no third flight"
    );
}

/// A payload that claims a member's identity while the signature belongs to another key yields no
/// session, fails at the signature check, and leaves no poisoned state: the responder accepts the
/// next honest dial.
#[tokio::test]
async fn fabricated_signer_rejected() {
    let receiver = sealed(19);
    let victim = node(20);
    let forger = Forger::new(seed(21), victim);
    let (accepted, _) = tokio::join!(receiver.accept(), forger.connect(dial_addr(&receiver)));
    assert!(accepted.is_err(), "a fabricated signer yields no session");

    let honest = sealed(22);
    let (accepted, dialed) = tokio::join!(receiver.accept(), honest.connect(dial_addr(&receiver)));
    assert_eq!(accepted.expect("accepted").peer(), node(22));
    dialed.expect("honest dial");
}

/// The hostile dialer case: a wire peer claims a member's `NodeId` while holding another key. The
/// accept side refuses at the signature check, and no session ever speaks for the member.
#[tokio::test]
async fn hostile_wire_dialer_claims_foreign_nodeid() {
    let receiver = sealed(38);
    let victim = node(39);
    let forger = Forger::new(seed(40), victim);
    let (accepted, _) = tokio::join!(receiver.accept(), forger.connect(dial_addr(&receiver)));

    match accepted {
        Err(Error::Accept(source)) => assert!(
            matches!(
                source.downcast_ref::<bifrost_noise::NoiseError>(),
                Some(bifrost_noise::NoiseError::SignatureInvalid)
            ),
            "the claim dies at the signature check"
        ),
        Err(_) => panic!("expected a signature failure"),
        Ok(session) => panic!("a foreign claim yielded a session for {}", session.peer()),
    }
}

/// A recorded flight replayed at a fresh responder yields no session, and the responder still
/// serves an honest dial afterwards.
#[tokio::test]
async fn handshake_replay_rejected() {
    let receiver = sealed(23);
    let dialer_inner = Wire::bind(seed(24));
    let written = dialer_inner.writes();
    let dialer = Noise::new(dialer_inner, seed(24)).expect("dialer");

    let (first, _) = tokio::join!(receiver.accept(), dialer.connect(dial_addr(&receiver)));
    first.expect("the first handshake completes");
    let flight = written.lock().unwrap_or_else(|p| p.into_inner()).clone();

    let replayer = Replayer::new(seed(25), flight);
    let (replayed, _) = tokio::join!(receiver.accept(), replayer.connect(dial_addr(&receiver)));
    match replayed {
        Err(Error::Accept(source)) => assert!(
            matches!(
                source.downcast_ref::<NoiseError>(),
                Some(NoiseError::Handshake(_))
            ),
            "the replayed third flight fails authentication"
        ),
        Err(_) => panic!("expected an accept failure"),
        Ok(_) => panic!("a replayed flight yields no session"),
    }

    let honest = sealed(26);
    let (accepted, _) = tokio::join!(receiver.accept(), honest.connect(dial_addr(&receiver)));
    assert_eq!(accepted.expect("accepted").peer(), node(26));
}

/// One inner stream carries two independent logical streams with interleaved writes.
#[tokio::test]
async fn two_streams_over_one_inner() {
    let receiver = sealed(27);
    let dialer = sealed(28);
    let (accepted, dialed) = tokio::join!(receiver.accept(), dialer.connect(dial_addr(&receiver)));
    let accepted = accepted.expect("accepted");
    let dialed = dialed.expect("dialed");

    let first = b"first stream";
    let second = b"second stream";

    let server = async {
        let (mut w1, mut r1) = accepted.accept_bi().await.expect("accept one");
        let (mut w2, mut r2) = accepted.accept_bi().await.expect("accept two");
        let mut b1 = vec![0u8; first.len()];
        let mut b2 = vec![0u8; second.len()];
        r1.read_exact(&mut b1).await.expect("read one");
        r2.read_exact(&mut b2).await.expect("read two");
        w1.write_all(&b1).await.expect("echo one");
        w1.shutdown().await.expect("finish one");
        w2.write_all(&b2).await.expect("echo two");
        w2.shutdown().await.expect("finish two");
    };
    let client = async {
        let (mut w1, mut r1) = dialed.open_bi().await.expect("open one");
        let (mut w2, mut r2) = dialed.open_bi().await.expect("open two");
        w1.write_all(first).await.expect("write one");
        w2.write_all(second).await.expect("write two");
        w1.shutdown().await.expect("finish one");
        w2.shutdown().await.expect("finish two");
        let mut e1 = vec![0u8; first.len()];
        let mut e2 = vec![0u8; second.len()];
        r1.read_exact(&mut e1).await.expect("echo one");
        r2.read_exact(&mut e2).await.expect("echo two");
        assert_eq!(e1.as_slice(), first);
        assert_eq!(e2.as_slice(), second);
    };

    tokio::join!(server, client);
}

/// Dropping a stream half without a shutdown sends `RESET`; the peer's read fails instead of
/// parking, and the session survives for its other streams.
#[tokio::test]
async fn dropped_stream_resets_the_peer() {
    let receiver = sealed(41);
    let dialer = sealed(42);
    let (accepted, dialed) = tokio::join!(receiver.accept(), dialer.connect(dial_addr(&receiver)));
    let accepted = accepted.expect("accepted");
    let dialed = dialed.expect("dialed");

    let server = async {
        let (_write, mut read) = accepted.accept_bi().await.expect("accept");
        let mut buf = [0u8; 5];
        read.read_exact(&mut buf).await.expect("data arrives");
        assert_eq!(&buf, b"hello");
        let reset = read.read(&mut buf).await.expect_err("the peer reset");
        assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);
    };
    let client = async {
        let (mut write, _read) = dialed.open_bi().await.expect("open");
        write.write_all(b"hello").await.expect("write");
        // No shutdown: dropping the half is an abandoned stream.
        drop(write);
    };

    tokio::join!(server, client);
}

/// A failed handshake is a typed failure, and the responder is not left parked.
#[tokio::test]
async fn forged_dial_fails_closed_with_a_typed_error() {
    let receiver = sealed(29);
    let forger = Forger::new(seed(30), node(31));
    let (accepted, _) = tokio::join!(receiver.accept(), forger.connect(dial_addr(&receiver)));
    match accepted {
        Err(Error::Accept(_)) => {}
        Err(other) => panic!("expected an accept failure, got {other}"),
        Ok(_) => panic!("a fabricated signer must yield no session"),
    }
}

/// A fatal frame fails the pending local read closed and wakes `wait_closed`, even though the peer
/// keeps the inner connection open; the listener then serves the next honest dial.
#[tokio::test]
async fn fatal_frame_closes_pending_streams_and_wakes_wait_closed() {
    let receiver = sealed(66);
    let saboteur = Saboteur::new(seed(67), Sabotage::UnknownData);
    let (accepted, saboteur) =
        tokio::join!(receiver.accept(), saboteur.connect(dial_addr(&receiver)));
    let accepted = accepted.expect("the handshake itself completes");
    let _saboteur = saboteur.expect("the dialer holds the connection");

    let (_write, mut read) = accepted
        .accept_bi()
        .await
        .expect("the open stream is queued");
    let mut buf = [0u8; 1];
    let reset = read
        .read(&mut buf)
        .await
        .expect_err("the fatal frame closes the read");
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);

    tokio::time::timeout(Duration::from_secs(1), accepted.wait_closed())
        .await
        .expect("wait_closed wakes on a fatal frame");

    let honest = sealed(68);
    let (next, _) = tokio::join!(receiver.accept(), honest.connect(dial_addr(&receiver)));
    assert_eq!(next.expect("the listener survives").peer(), node(68));
}

/// A frame prefix past the ciphertext cap is fatal, and the listener survives it.
#[tokio::test]
async fn oversized_session_frame_is_fatal() {
    let receiver = sealed(69);
    let saboteur = Saboteur::new(seed(70), Sabotage::OversizedPrefix);
    let (accepted, saboteur) =
        tokio::join!(receiver.accept(), saboteur.connect(dial_addr(&receiver)));
    let accepted = accepted.expect("the handshake itself completes");
    let _saboteur = saboteur.expect("the dialer holds the connection");

    let (_write, mut read) = accepted
        .accept_bi()
        .await
        .expect("the open stream is queued");
    let mut buf = [0u8; 1];
    let reset = read
        .read(&mut buf)
        .await
        .expect_err("the bad prefix closes the read");
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);
}

/// A replayed frame ciphertext delivers exactly once and then tears the session down.
#[tokio::test]
async fn replayed_session_frame_delivers_once() {
    let receiver = sealed(71);
    let saboteur = Saboteur::new(seed(72), Sabotage::ReplayedFrame);
    let (accepted, saboteur) =
        tokio::join!(receiver.accept(), saboteur.connect(dial_addr(&receiver)));
    let accepted = accepted.expect("the handshake itself completes");
    let _saboteur = saboteur.expect("the dialer holds the connection");

    let (_write, mut read) = accepted
        .accept_bi()
        .await
        .expect("the open stream is queued");
    let mut payload = [0u8; 7];
    read.read_exact(&mut payload)
        .await
        .expect("the first frame delivers");
    assert_eq!(&payload, b"payload");
    let mut extra = [0u8; 1];
    let reset = read
        .read(&mut extra)
        .await
        .expect_err("the replay is fatal");
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);
}

/// A bare peer's wrong tag is rejected with `BadTag` and the listener survives.
#[tokio::test]
async fn bare_peer_tag_is_rejected_and_listener_survives() {
    let receiver = sealed(73);
    let bare = BarePeer::new(seed(74));
    let (accepted, _bare) = tokio::join!(receiver.accept(), bare.connect(dial_addr(&receiver)));
    match accepted {
        Err(Error::Accept(source)) => assert!(
            matches!(
                source.downcast_ref::<NoiseError>(),
                Some(NoiseError::BadTag)
            ),
            "a wrong tag is a tag failure"
        ),
        Err(_) => panic!("expected a tag failure"),
        Ok(_) => panic!("a bare peer must not negotiate a wrapper session"),
    }

    let honest = sealed(75);
    let (next, _) = tokio::join!(receiver.accept(), honest.connect(dial_addr(&receiver)));
    assert_eq!(next.expect("the listener survives").peer(), node(75));
}

/// A third message spliced from another session is refused at authentication, and the listener
/// survives.
#[tokio::test]
async fn spliced_msg3_is_rejected_and_listener_survives() {
    // Record one honest flight and lift its third message.
    let recording_receiver = sealed(76);
    let dialer_inner = Wire::bind(seed(77));
    let written = dialer_inner.writes();
    let dialer = Noise::new(dialer_inner, seed(77)).expect("dialer");
    let (first, _) = tokio::join!(
        recording_receiver.accept(),
        dialer.connect(dial_addr(&recording_receiver))
    );
    first.expect("the recorded handshake completes");
    let flight = written.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let third = third_frame(&flight)
        .expect("the flight has a third frame")
        .to_vec();

    let receiver = sealed(78);
    let splicer = Splicer::new(seed(79), third);
    let (accepted, _splicer) =
        tokio::join!(receiver.accept(), splicer.connect(dial_addr(&receiver)));
    match accepted {
        Err(Error::Accept(source)) => assert!(
            matches!(
                source.downcast_ref::<NoiseError>(),
                Some(NoiseError::Handshake(_))
            ),
            "the spliced third fails authentication"
        ),
        Err(_) => panic!("expected an accept failure"),
        Ok(_) => panic!("a spliced third must yield no session"),
    }

    let honest = sealed(80);
    let (next, _) = tokio::join!(receiver.accept(), honest.connect(dial_addr(&receiver)));
    assert_eq!(next.expect("the listener survives").peer(), node(80));
}

/// The wrapper seals application bytes: a marker written through it never appears on the inner
/// wire, on either side.
#[tokio::test]
async fn application_bytes_do_not_appear_on_the_inner_wire() {
    let receiver_inner = Wire::bind(seed(81));
    let receiver_written = receiver_inner.writes();
    let receiver = Noise::new(receiver_inner, seed(81)).expect("receiver");
    let dialer_inner = Wire::bind(seed(82));
    let dialer_written = dialer_inner.writes();
    let dialer = Noise::new(dialer_inner, seed(82)).expect("dialer");

    let (accepted, dialed) = tokio::join!(receiver.accept(), dialer.connect(dial_addr(&receiver)));
    let accepted = accepted.expect("accepted");
    let dialed = dialed.expect("dialed");

    let marker: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let server = async {
        let (_write, mut read) = accepted.accept_bi().await.expect("accept");
        let mut got = vec![0u8; marker.len()];
        read.read_exact(&mut got).await.expect("read the marker");
        assert_eq!(got, marker);
    };
    let client = async {
        let (mut write, _read) = dialed.open_bi().await.expect("open");
        write.write_all(&marker).await.expect("write");
        write.shutdown().await.expect("finish");
    };
    tokio::join!(server, client);

    for log in [dialer_written, receiver_written] {
        let bytes = log.lock().unwrap_or_else(|p| p.into_inner()).clone();
        assert!(
            !bytes
                .windows(marker.len())
                .any(|window| window == marker.as_slice()),
            "the marker must never appear in the inner bytes"
        );
    }
}

/// The stream cap counts concurrent streams, not a session lifetime: a closed stream frees a slot.
#[tokio::test]
async fn stream_cap_counts_concurrent_streams() {
    // The ratified bound, `session.rs` MAX_STREAMS.
    const MAX_STREAMS: usize = 64;
    let receiver = sealed(83);
    let dialer = sealed(84);
    let (accepted, dialed) = tokio::join!(receiver.accept(), dialer.connect(dial_addr(&receiver)));
    let _accepted = accepted.expect("accepted");
    let dialed = dialed.expect("dialed");

    let mut open = Vec::new();
    for _ in 0..MAX_STREAMS {
        open.push(dialed.open_bi().await.expect("under the cap"));
    }
    match dialed.open_bi().await {
        Err(Error::Stream(source)) => assert!(
            matches!(
                source.downcast_ref::<NoiseError>(),
                Some(NoiseError::TooManyStreams)
            ),
            "the cap is a typed refusal"
        ),
        Err(_) => panic!("expected a stream failure"),
        Ok(_) => panic!("the cap must hold"),
    }
    drop(open.pop());
    dialed
        .open_bi()
        .await
        .expect("a closed stream frees its slot");
}
