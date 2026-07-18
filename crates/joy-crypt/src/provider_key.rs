//! Provider API-key wrapping for AI members (the zone-grant pattern
//! applied to secrets that must travel IN the repo).
//!
//! The key OWNER wraps the plaintext key pairwise (X25519 ECDH, see
//! [`crate::pairwise`]) for each entitled recipient: themselves, the
//! platform (so server-run containers can use it while the owner is
//! offline), and — when the key is released for the whole team — every
//! member with an identity key. Each recipient unwraps with the mirror
//! computation from the OWNER's public key; nobody else can, and the
//! repo carries only ciphertext.
//!
//! The `info` binding ties a wrap to the AI member it powers, so the
//! same (owner, recipient) pair yields distinct KEKs per agent.

use crate::error::Error;
use crate::pairwise::pairwise_kek;
use crate::wrap::{unwrap, wrap};

/// The KEK info binding for an AI member's provider key. Shared verbatim
/// by every implementation (CLI, platform, browser WASM) — a mismatch
/// would silently derive a different KEK.
pub fn provider_key_info(ai_member: &str) -> Vec<u8> {
    format!("provider-key:{ai_member}").into_bytes()
}

/// Wrap `api_key` from the owner to one recipient. `owner_x25519_secret`
/// comes from the owner's identity keypair, `recipient_x25519_public`
/// from the recipient's verify_key on record. Hex out.
pub fn wrap_provider_key(
    owner_x25519_secret: &[u8; 32],
    recipient_x25519_public: &[u8; 32],
    ai_member: &str,
    api_key: &str,
) -> String {
    let kek = pairwise_kek(
        owner_x25519_secret,
        recipient_x25519_public,
        &provider_key_info(ai_member),
    );
    hex::encode(wrap(&kek, api_key.as_bytes()))
}

/// Unwrap a provider key as one of its recipients, from the owner's
/// public key.
pub fn unwrap_provider_key(
    recipient_x25519_secret: &[u8; 32],
    owner_x25519_public: &[u8; 32],
    ai_member: &str,
    wrapped_hex: &str,
) -> Result<String, Error> {
    let kek = pairwise_kek(
        recipient_x25519_secret,
        owner_x25519_public,
        &provider_key_info(ai_member),
    );
    let wrapped = hex::decode(wrapped_hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
    let plain = unwrap(&kek, &wrapped)?;
    String::from_utf8(plain).map_err(|_| Error::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    #[test]
    fn owner_platform_and_teammate_each_unwrap_their_copy() {
        let owner = Keypair::from_seed(&[1u8; 32]);
        let platform = Keypair::from_seed(&[2u8; 32]);
        let teammate = Keypair::from_seed(&[3u8; 32]);
        let api_key = "sk-super-secret";

        let for_platform = wrap_provider_key(
            &owner.to_x25519_secret_bytes(),
            &platform.public_key().to_x25519_public_bytes(),
            "ai:mistral@joy",
            api_key,
        );
        let for_self = wrap_provider_key(
            &owner.to_x25519_secret_bytes(),
            &owner.public_key().to_x25519_public_bytes(),
            "ai:mistral@joy",
            api_key,
        );
        let for_teammate = wrap_provider_key(
            &owner.to_x25519_secret_bytes(),
            &teammate.public_key().to_x25519_public_bytes(),
            "ai:mistral@joy",
            api_key,
        );

        let owner_pub = owner.public_key().to_x25519_public_bytes();
        assert_eq!(
            unwrap_provider_key(
                &platform.to_x25519_secret_bytes(),
                &owner_pub,
                "ai:mistral@joy",
                &for_platform,
            )
            .unwrap(),
            api_key
        );
        assert_eq!(
            unwrap_provider_key(
                &owner.to_x25519_secret_bytes(),
                &owner_pub,
                "ai:mistral@joy",
                &for_self,
            )
            .unwrap(),
            api_key
        );
        assert_eq!(
            unwrap_provider_key(
                &teammate.to_x25519_secret_bytes(),
                &owner_pub,
                "ai:mistral@joy",
                &for_teammate,
            )
            .unwrap(),
            api_key
        );

        // the wrong recipient cannot unwrap a copy that is not theirs
        assert!(unwrap_provider_key(
            &teammate.to_x25519_secret_bytes(),
            &owner_pub,
            "ai:mistral@joy",
            &for_platform,
        )
        .is_err());
        // the binding bites: the same wrap under another agent fails
        assert!(unwrap_provider_key(
            &platform.to_x25519_secret_bytes(),
            &owner_pub,
            "ai:claude@joy",
            &for_platform,
        )
        .is_err());
    }
}
