//! The wrapper handshake: `Noise_XX_25519_ChaChaPoly_SHA256` with signed, fresh statics.
//!
//! Each side generates a fresh X25519 static for the handshake and signs the running handshake hash
//! together with that static under its ed25519 identity. The statics travel in the XX static tokens;
//! the signatures travel in the encrypted payload of messages two and three as `NodeId || sig`. The
//! accept side proves the peer at exactly one point: after message three decrypts, the signature is
//! verified over `CTX || h2 || S_i` under the identity named in the payload, where `h2` is the
//! handshake hash captured after message two was written and `S_i` is the static the DH actually
//! used. No session exists before that check passes.

use bifrost_core::{CryptoKind, NodeId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zeroize::Zeroize;

use crate::error::NoiseError;
use crate::wire;

/// A completed handshake: transport-mode state and the proven peer identity.
pub(crate) struct Established {
    /// The transport cipherstates, ready for framed messages.
    pub(crate) state: TransportState,
    /// The proven peer identity.
    pub(crate) peer: NodeId,
}

/// Run the initiator side of the handshake over one inner stream.
///
/// The responder's signature is verified under `dialed` (the address authority), and a claimed
/// signer different from `dialed` is refused before message three is written. `local` is the
/// wrapper's own identity; it is advertised in the message-three payload and must match `identity`.
pub(crate) async fn initiate<W, R>(
    write: &mut W,
    read: &mut R,
    identity: &SigningKey,
    local: NodeId,
    dialed: NodeId,
) -> Result<Established, NoiseError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let (mut state, local_static) = handshake_state(true)?;

    write_tag(write).await?;
    read_tag(read).await?;

    let mut message = vec![0u8; wire::MAX_HANDSHAKE_MESSAGE];
    let len = state
        .write_message(&[], &mut message)
        .map_err(NoiseError::Handshake)?;
    send_frame(write, &message[..len]).await?;
    let h1 = hash(&state);

    let reply = read_frame(read, wire::MAX_HANDSHAKE_MESSAGE).await?;
    let mut payload = vec![0u8; wire::MAX_HANDSHAKE_MESSAGE];
    let len = state
        .read_message(&reply, &mut payload)
        .map_err(NoiseError::Handshake)?;
    let (claimed, signature) = parse_payload(&payload[..len])?;
    if claimed != dialed {
        return Err(NoiseError::SignerMismatch { dialed, claimed });
    }
    let remote_static = state
        .get_remote_static()
        .ok_or(NoiseError::MalformedPayload)?;
    verify_signature(&dialed, wire::CTX_RESPONDER, &h1, remote_static, &signature)?;
    let h2 = hash(&state);

    let signature = sign(identity, wire::CTX_INITIATOR, &h2, &local_static);
    let payload = encode_payload(&local, &signature);
    let len = state
        .write_message(&payload, &mut message)
        .map_err(NoiseError::Handshake)?;
    send_frame(write, &message[..len]).await?;

    Ok(Established {
        state: into_transport(state)?,
        peer: dialed,
    })
}

/// Run the responder side of the handshake over one inner stream.
///
/// The peer's identity is proven after message three decrypts: the payload's signer must verify
/// over `CTX || h2 || S_i` under its own key, with `h2` captured after message two was written and
/// `S_i` read back from the handshake state. Nothing is trusted from the payload before that.
pub(crate) async fn respond<W, R>(
    write: &mut W,
    read: &mut R,
    identity: &SigningKey,
    local: NodeId,
) -> Result<Established, NoiseError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let (mut state, local_static) = handshake_state(false)?;

    write_tag(write).await?;
    read_tag(read).await?;

    let mut message = vec![0u8; wire::MAX_HANDSHAKE_MESSAGE];
    let first = read_frame(read, wire::MAX_HANDSHAKE_MESSAGE).await?;
    let mut payload = vec![0u8; wire::MAX_HANDSHAKE_MESSAGE];
    let len = state
        .read_message(&first, &mut payload)
        .map_err(NoiseError::Handshake)?;
    // XX message one carries an ephemeral and nothing else; a pre-DH payload has no key to hide
    // under, so it is never part of the protocol.
    if len != 0 {
        return Err(NoiseError::MalformedPayload);
    }
    let h1 = hash(&state);

    let signature = sign(identity, wire::CTX_RESPONDER, &h1, &local_static);
    let reply = encode_payload(&local, &signature);
    let len = state
        .write_message(&reply, &mut message)
        .map_err(NoiseError::Handshake)?;
    let h2 = hash(&state);
    send_frame(write, &message[..len]).await?;

    let third = read_frame(read, wire::MAX_HANDSHAKE_MESSAGE).await?;
    let len = state
        .read_message(&third, &mut payload)
        .map_err(NoiseError::Handshake)?;
    let (claimed, signature) = parse_payload(&payload[..len])?;
    let remote_static = state
        .get_remote_static()
        .ok_or(NoiseError::MalformedPayload)?;
    verify_signature(
        &claimed,
        wire::CTX_INITIATOR,
        &h2,
        remote_static,
        &signature,
    )?;

    Ok(Established {
        state: into_transport(state)?,
        peer: claimed,
    })
}

/// Build a handshake state with a fresh X25519 static and return the static's public bytes.
///
/// The private half is copied into the handshake state and zeroized here; nothing outlives the
/// handshake but the public bytes the peer checks the signature against.
pub(crate) fn handshake_state(
    initiator: bool,
) -> Result<(HandshakeState, [u8; NodeId::KEY_LEN]), NoiseError> {
    let params: NoiseParams = wire::PATTERN
        .parse()
        .map_err(|_| NoiseError::UnsupportedPattern)?;
    let builder = Builder::new(params)
        .prologue(wire::PROLOGUE)
        .map_err(NoiseError::Handshake)?;
    let mut keypair = builder
        .generate_keypair()
        .map_err(|_| NoiseError::RngUnavailable)?;
    let public: [u8; NodeId::KEY_LEN] = keypair
        .public
        .as_slice()
        .try_into()
        .map_err(|_| NoiseError::KeyLength)?;
    let builder = builder
        .local_private_key(&keypair.private)
        .map_err(NoiseError::Handshake)?;
    let state = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(NoiseError::Handshake)?;
    keypair.private.zeroize();
    Ok((state, public))
}

/// Sign `CTX_role || h_prev || own_static` under the wrapper's identity.
pub(crate) fn sign(
    identity: &SigningKey,
    context: &[u8],
    h_prev: &[u8],
    own_static: &[u8],
) -> Signature {
    identity.sign(&signed_bytes(context, h_prev, own_static))
}

/// Verify a handshake signature under the identity that must own the signed static.
pub(crate) fn verify_signature(
    signer: &NodeId,
    context: &[u8],
    h_prev: &[u8],
    own_static: &[u8],
    signature: &Signature,
) -> Result<(), NoiseError> {
    let signed = signed_bytes(context, h_prev, own_static);
    match signer.kind() {
        CryptoKind::Ed25519 => {
            let key =
                VerifyingKey::from_bytes(signer.key()).map_err(|_| NoiseError::SignatureInvalid)?;
            key.verify_strict(&signed, signature)
                .map_err(|_| NoiseError::SignatureInvalid)
        }
    }
}

/// The exact bytes a handshake signature covers, in order: role context, previous hash, static.
fn signed_bytes(context: &[u8], h_prev: &[u8], own_static: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(context.len() + h_prev.len() + own_static.len());
    signed.extend_from_slice(context);
    signed.extend_from_slice(h_prev);
    signed.extend_from_slice(own_static);
    signed
}

/// Encode the fixed payload `NodeId || signature`.
pub(crate) fn encode_payload(signer: &NodeId, signature: &Signature) -> Vec<u8> {
    let mut payload = Vec::with_capacity(wire::PAYLOAD_LEN);
    payload.extend_from_slice(signer.key());
    payload.extend_from_slice(&signature.to_bytes());
    payload
}

/// Parse the fixed payload `NodeId || signature`, rejecting any other length or encoding.
pub(crate) fn parse_payload(payload: &[u8]) -> Result<(NodeId, Signature), NoiseError> {
    if payload.len() != wire::PAYLOAD_LEN {
        return Err(NoiseError::MalformedPayload);
    }
    let key: [u8; NodeId::KEY_LEN] = payload[..NodeId::KEY_LEN]
        .try_into()
        .map_err(|_| NoiseError::MalformedPayload)?;
    let signature = Signature::from_slice(&payload[NodeId::KEY_LEN..])
        .map_err(|_| NoiseError::SignatureInvalid)?;
    Ok((NodeId::new(CryptoKind::Ed25519, key), signature))
}

/// Send the cleartext tag, flushed so the peer can read it before any handshake message.
async fn write_tag<W: AsyncWrite + Unpin>(write: &mut W) -> Result<(), NoiseError> {
    write.write_all(wire::TAG).await?;
    write.flush().await?;
    Ok(())
}

/// Read exactly the tag and compare it; anything else is a protocol mismatch, not a fallback.
async fn read_tag<R: AsyncRead + Unpin>(read: &mut R) -> Result<(), NoiseError> {
    let mut tag = [0u8; wire::TAG.len()];
    read.read_exact(&mut tag).await?;
    if tag.as_slice() != wire::TAG {
        return Err(NoiseError::BadTag);
    }
    Ok(())
}

/// Write one length-prefixed Noise message.
pub(crate) async fn send_frame<W: AsyncWrite + Unpin>(
    write: &mut W,
    message: &[u8],
) -> Result<(), NoiseError> {
    let len = u16::try_from(message.len()).map_err(|_| NoiseError::MessageTooLarge {
        len: message.len(),
        max: usize::from(u16::MAX),
    })?;
    write.write_all(&len.to_be_bytes()).await?;
    write.write_all(message).await?;
    write.flush().await?;
    Ok(())
}

/// Read one length-prefixed Noise message, checking the prefix against `max` before allocating.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    read: &mut R,
    max: usize,
) -> Result<Vec<u8>, NoiseError> {
    let mut len = [0u8; 2];
    read.read_exact(&mut len).await?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > max {
        return Err(NoiseError::MessageTooLarge { len, max });
    }
    let mut message = vec![0u8; len];
    read.read_exact(&mut message).await?;
    Ok(message)
}

/// Copy the running handshake hash; the hash moves on with every message.
fn hash(state: &HandshakeState) -> Vec<u8> {
    state.get_handshake_hash().to_vec()
}

/// Move a finished handshake into transport mode, checking the state is actually finished.
fn into_transport(state: HandshakeState) -> Result<TransportState, NoiseError> {
    if !state.is_handshake_finished() {
        return Err(NoiseError::MalformedPayload);
    }
    state.into_transport_mode().map_err(NoiseError::Handshake)
}
