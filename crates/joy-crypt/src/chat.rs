// Copyright (c) 2026 Joydev GmbH (joydev.com)
// SPDX-License-Identifier: LicenseRef-Commercial

//! Chat content-key primitives (ADR JAPP-002A-30 in the app repo).
//!
//! THE shared half of per-chat encryption: joy-core seals and opens
//! chats on the server and desktop through these functions, and the
//! browser (joyint-web-auth WASM) opens them with exactly the same
//! code, so the two sides can never drift apart. joy-core additionally
//! owns the model plumbing (wrap header in the chat object, epochs,
//! participant resolution); nothing here knows the chat model.
//!
//! Formats, fixed here and nowhere else:
//! - wrap KEK info: `crypt-zone:chat:<chat_id>#<epoch>` (the generic
//!   member-wrap derivation of joy-core::crypt with the chat wrap name)
//! - wrap bytes: `granter_verify_key(32) || wrap(kek, content_key)`, hex
//! - message envelope: hex `nonce(12) || AES-256-GCM ct` over the
//!   sensitive-fields JSON, AAD `JOYCHAT:<chat_id>#<epoch>:<msg_id>`

use crate::error::Error;
use crate::identity::PublicKey;
use crate::pairwise::pairwise_kek;
use crate::{aead, wrap};

/// The KEK info bytes for a chat wrap: the generic member-wrap prefix
/// (`crypt-zone:`) applied to the chat wrap name.
pub fn kek_info(chat_id: &str, epoch: u32) -> Vec<u8> {
    format!("crypt-zone:chat:{chat_id}#{epoch}").into_bytes()
}

/// AAD binding a sealed message to its chat, epoch and message id.
pub fn aad(chat_id: &str, epoch: u32, msg_id: &str) -> Vec<u8> {
    format!("JOYCHAT:{chat_id}#{epoch}:{msg_id}").into_bytes()
}

/// Unwrap a chat content key with the recipient's X25519 secret. The
/// granter's verify_key rides the wrap header (first 32 bytes).
pub fn unwrap_content_key(
    recipient_x25519_secret: &[u8; 32],
    wrap_hex: &str,
    chat_id: &str,
    epoch: u32,
) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(wrap_hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
    if bytes.len() < 32 {
        return Err(Error::InvalidLength {
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut granter_pk = [0u8; 32];
    granter_pk.copy_from_slice(&bytes[..32]);
    let granter_x25519 = PublicKey::from_hex(&hex::encode(granter_pk))?.to_x25519_public_bytes();
    let kek = pairwise_kek(
        recipient_x25519_secret,
        &granter_x25519,
        &kek_info(chat_id, epoch),
    );
    let plain = wrap::unwrap(&kek, &bytes[32..])?;
    let got = plain.len();
    plain
        .try_into()
        .map_err(|_| Error::InvalidLength { expected: 32, got })
}

/// Open one sealed message envelope; returns the sensitive-fields JSON.
pub fn open_envelope(
    key: &[u8; 32],
    chat_id: &str,
    epoch: u32,
    msg_id: &str,
    enc_hex: &str,
) -> Result<Vec<u8>, Error> {
    let blob = hex::decode(enc_hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
    if blob.len() < 12 + 16 {
        return Err(Error::InvalidLength {
            expected: 12 + 16,
            got: blob.len(),
        });
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    aead::open(key, &nonce, &aad(chat_id, epoch, msg_id), &blob[12..])
}
