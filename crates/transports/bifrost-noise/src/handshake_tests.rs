use bifrost_core::NodeId;
use ed25519_dalek::{Signer as _, SigningKey};
use snow::Builder;
use snow::params::NoiseParams;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex, split};

use crate::error::NoiseError;
use crate::handshake::{
    encode_payload, handshake_state, initiate, parse_payload, respond, send_frame, sign,
    verify_signature,
};
use crate::wire;

fn seed(byte: u8) -> [u8; NodeId::KEY_LEN] {
    [byte; NodeId::KEY_LEN]
}

/// Every handshake generates a fresh static; nothing is cached across sessions.
#[test]
fn fresh_statics_differ_per_handshake() {
    let (_, first) = handshake_state(false).expect("first handshake state");
    let (_, second) = handshake_state(false).expect("second handshake state");
    assert_ne!(first, second, "each handshake must generate a fresh static");
}

/// The payload is exactly `NodeId || signature`; a moved layout or a trailing byte is refused.
#[test]
fn payload_layout_is_frozen() {
    let identity = SigningKey::from_bytes(&seed(3));
    let node = NodeId::from_ed25519_secret(&seed(3));
    let signature = sign(&identity, wire::CTX_INITIATOR, &[0u8; 32], &[9u8; 32]);
    let payload = encode_payload(&node, &signature);

    assert_eq!(payload.len(), wire::PAYLOAD_LEN);
    assert_eq!(&payload[..NodeId::KEY_LEN], node.key());
    assert_eq!(&payload[NodeId::KEY_LEN..], &signature.to_bytes()[..]);

    let (parsed, parsed_signature) = parse_payload(&payload).expect("the canonical payload parses");
    assert_eq!(parsed, node);
    assert_eq!(parsed_signature, signature);

    let mut moved = Vec::with_capacity(wire::PAYLOAD_LEN);
    moved.extend_from_slice(&signature.to_bytes());
    moved.extend_from_slice(node.key());
    // A signature-first arrangement cannot read back as the same identity: the 32 bytes the parser
    // takes for a NodeId are signature material here.
    if let Ok((parsed, _)) = parse_payload(&moved) {
        assert_ne!(parsed, node, "signature-first is not the layout");
    }

    let mut trailing = payload.clone();
    trailing.push(0);
    assert!(
        matches!(parse_payload(&trailing), Err(NoiseError::MalformedPayload)),
        "trailing bytes are not a payload"
    );
    assert!(
        matches!(
            parse_payload(&payload[..NodeId::KEY_LEN]),
            Err(NoiseError::MalformedPayload)
        ),
        "a static-width payload is not a payload"
    );
}

/// A signature is bound to one transcript: lifting it into another session, another role, or
/// another use of the same key fails, and the same transcript verifies.
#[test]
fn signature_transplant_rejected() {
    let identity = SigningKey::from_bytes(&seed(4));
    let signer = NodeId::from_ed25519_secret(&seed(4));
    let hash_a = [1u8; 32];
    let hash_b = [2u8; 32];
    let static_key = [7u8; 32];
    let signature = sign(&identity, wire::CTX_INITIATOR, &hash_a, &static_key);

    assert!(
        verify_signature(
            &signer,
            wire::CTX_INITIATOR,
            &hash_a,
            &static_key,
            &signature
        )
        .is_ok(),
        "the signed transcript verifies"
    );
    assert!(
        matches!(
            verify_signature(
                &signer,
                wire::CTX_RESPONDER,
                &hash_a,
                &static_key,
                &signature
            ),
            Err(NoiseError::SignatureInvalid)
        ),
        "another role context fails"
    );
    assert!(
        matches!(
            verify_signature(
                &signer,
                wire::CTX_INITIATOR,
                &hash_b,
                &static_key,
                &signature
            ),
            Err(NoiseError::SignatureInvalid)
        ),
        "another session's hash fails"
    );
    assert!(
        matches!(
            verify_signature(
                &signer,
                wire::CTX_INITIATOR,
                &hash_a,
                &[8u8; 32],
                &signature
            ),
            Err(NoiseError::SignatureInvalid)
        ),
        "another static fails"
    );
    let other = NodeId::from_ed25519_secret(&seed(5));
    assert!(
        matches!(
            verify_signature(
                &other,
                wire::CTX_INITIATOR,
                &hash_a,
                &static_key,
                &signature
            ),
            Err(NoiseError::SignatureInvalid)
        ),
        "another signer fails"
    );

    // Same-key document signature: the shape matches, the signed bytes do not.
    let document = identity.sign(b"a signed document");
    assert!(
        matches!(
            verify_signature(
                &signer,
                wire::CTX_INITIATOR,
                &hash_a,
                &static_key,
                &document
            ),
            Err(NoiseError::SignatureInvalid)
        ),
        "a document signature is not a handshake signature"
    );
}

/// A payload that claims a victim's identity while the signature belongs to another key fails the
/// verification under the claimed identity.
#[test]
fn fabricated_signer_rejected() {
    let holder = SigningKey::from_bytes(&seed(6));
    let victim = NodeId::from_ed25519_secret(&seed(7));
    let hash = [3u8; 32];
    let static_key = [4u8; 32];

    let signature = sign(&holder, wire::CTX_INITIATOR, &hash, &static_key);
    let payload = encode_payload(&victim, &signature);
    let (claimed, parsed) = parse_payload(&payload).expect("the payload parses");
    assert_eq!(claimed, victim, "the payload claims the victim");
    assert!(
        matches!(
            verify_signature(&claimed, wire::CTX_INITIATOR, &hash, &static_key, &parsed),
            Err(NoiseError::SignatureInvalid)
        ),
        "the claim cannot be backed by the wrong key"
    );
}

/// Length-prefixed messages round-trip, and a prefix past the bound is refused before the body.
#[tokio::test]
async fn messages_are_length_prefixed_and_bounded() {
    let (mut writer, mut reader) = duplex(4096);
    let sent = tokio::spawn(async move { send_frame(&mut writer, &[9u8; 100]).await });
    let received = crate::handshake::read_frame(&mut reader, 1024)
        .await
        .expect("read the frame");
    assert_eq!(received, [9u8; 100]);
    sent.await.expect("writer task").expect("send");

    let (mut writer, mut reader) = duplex(4096);
    writer
        .write_all(&5000u16.to_be_bytes())
        .await
        .expect("write the oversized prefix");
    assert!(
        matches!(
            crate::handshake::read_frame(&mut reader, 1024).await,
            Err(NoiseError::MessageTooLarge {
                len: 5000,
                max: 1024
            })
        ),
        "the prefix is checked before any allocation"
    );
}

/// XX message one carries only an ephemeral. A payload there (a pre-DH identity placement) is
/// refused before any key exists to hide it under.
#[tokio::test]
async fn node_id_in_message_one_is_rejected() {
    let responder_seed = seed(8);
    let responder_node = NodeId::from_ed25519_secret(&responder_seed);
    let (initiator_head, responder_head) = duplex(64 * 1024);

    let responder = tokio::spawn(async move {
        let (mut read, mut write) = split(responder_head);
        respond(
            &mut write,
            &mut read,
            &SigningKey::from_bytes(&responder_seed),
            responder_node,
        )
        .await
    });

    let (mut read, mut write) = split(initiator_head);
    write.write_all(wire::TAG).await.expect("tag");
    write.flush().await.expect("flush");
    let mut tag = [0u8; wire::TAG.len()];
    read.read_exact(&mut tag).await.expect("peer tag");
    assert_eq!(tag.as_slice(), wire::TAG);

    let params: NoiseParams = wire::PATTERN.parse().expect("pattern");
    let builder = Builder::new(params)
        .prologue(wire::PROLOGUE)
        .expect("prologue");
    let keypair = builder.generate_keypair().expect("static");
    let mut state = builder
        .local_private_key(&keypair.private)
        .expect("private key")
        .build_initiator()
        .expect("initiator");
    let payload = [1u8; wire::PAYLOAD_LEN];
    let mut message = vec![0u8; 1024];
    let len = state
        .write_message(&payload, &mut message)
        .expect("message one");
    send_frame(&mut write, &message[..len])
        .await
        .expect("send message one");

    let result = responder.await.expect("responder task");
    assert!(
        matches!(result, Err(NoiseError::MalformedPayload)),
        "a pre-DH payload is not part of the protocol"
    );
}

/// The honest handshake completes and each side attributes the other's identity.
#[tokio::test]
async fn honest_handshake_binds_both_sides() {
    let initiator_seed = seed(10);
    let responder_seed = seed(11);
    let initiator_node = NodeId::from_ed25519_secret(&initiator_seed);
    let responder_node = NodeId::from_ed25519_secret(&responder_seed);
    let (initiator_head, responder_head) = duplex(64 * 1024);

    let responder = tokio::spawn(async move {
        let (mut read, mut write) = split(responder_head);
        respond(
            &mut write,
            &mut read,
            &SigningKey::from_bytes(&responder_seed),
            responder_node,
        )
        .await
    });

    let (mut read, mut write) = split(initiator_head);
    let established = initiate(
        &mut write,
        &mut read,
        &SigningKey::from_bytes(&initiator_seed),
        initiator_node,
        responder_node,
    )
    .await
    .expect("initiator");
    let established_responder = responder.await.expect("responder task").expect("responder");

    assert_eq!(established.peer, responder_node);
    assert_eq!(established_responder.peer, initiator_node);
}
