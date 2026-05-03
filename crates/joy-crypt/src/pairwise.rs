//! Pairwise X25519 ECDH for Crypt zone-key wrapping.
//!
//! When a member grants another member access to a zone, the granter
//! wraps the zone key under a KEK derived from
//! `ECDH(granter_x25519_secret, recipient_x25519_public)`. The recipient
//! reproduces the same KEK with
//! `ECDH(recipient_x25519_secret, granter_x25519_public)`. The two
//! computations yield the same shared secret because Diffie-Hellman is
//! commutative over the curve.
//!
//! HKDF-SHA256 derives the final KEK from the shared secret. The `info`
//! parameter binds the wrap to a specific zone so the same
//! (granter, recipient) pair gets distinct KEKs across zones.
//!
//! Self-wrap (auto-create) is the special case where granter and
//! recipient are the same member: ECDH(self_secret, self_public) is a
//! deterministic value that only the holder of `self_secret` can
//! reproduce.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::kdf::derive_hkdf_sha256;

/// Compute the pairwise KEK between a local secret and a peer public,
/// salted with `info` (typically the zone name plus a fixed tag).
pub fn pairwise_kek(my_x25519_secret: &[u8; 32], peer_x25519_public: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let secret = StaticSecret::from(*my_x25519_secret);
    let peer = PublicKey::from(*peer_x25519_public);
    let shared = secret.diffie_hellman(&peer);
    derive_hkdf_sha256(shared.as_bytes(), b"crypt-pairwise-v1", info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Keypair, PublicKey as IdPublicKey};

    fn roundtrip_pair() -> (Keypair, Keypair) {
        (Keypair::from_seed(&[1u8; 32]), Keypair::from_seed(&[2u8; 32]))
    }

    #[test]
    fn ecdh_is_symmetric() {
        let (alice, bob) = roundtrip_pair();
        let kek_a = pairwise_kek(
            &alice.to_x25519_secret_bytes(),
            &bob.public_key().to_x25519_public_bytes(),
            b"zone:default",
        );
        let kek_b = pairwise_kek(
            &bob.to_x25519_secret_bytes(),
            &alice.public_key().to_x25519_public_bytes(),
            b"zone:default",
        );
        assert_eq!(kek_a, kek_b);
    }

    #[test]
    fn third_party_gets_different_kek() {
        let (alice, bob) = roundtrip_pair();
        let eve = Keypair::from_seed(&[9u8; 32]);
        let kek_ab = pairwise_kek(
            &alice.to_x25519_secret_bytes(),
            &bob.public_key().to_x25519_public_bytes(),
            b"zone:default",
        );
        let kek_eb = pairwise_kek(
            &eve.to_x25519_secret_bytes(),
            &bob.public_key().to_x25519_public_bytes(),
            b"zone:default",
        );
        assert_ne!(kek_ab, kek_eb);
    }

    #[test]
    fn distinct_zones_get_distinct_keks() {
        let (alice, bob) = roundtrip_pair();
        let kek_default = pairwise_kek(
            &alice.to_x25519_secret_bytes(),
            &bob.public_key().to_x25519_public_bytes(),
            b"zone:default",
        );
        let kek_other = pairwise_kek(
            &alice.to_x25519_secret_bytes(),
            &bob.public_key().to_x25519_public_bytes(),
            b"zone:customer-x",
        );
        assert_ne!(kek_default, kek_other);
    }

    #[test]
    fn self_wrap_is_deterministic() {
        let alice = Keypair::from_seed(&[5u8; 32]);
        let pk = alice.public_key();
        let a = pairwise_kek(
            &alice.to_x25519_secret_bytes(),
            &pk.to_x25519_public_bytes(),
            b"zone:default",
        );
        let b = pairwise_kek(
            &alice.to_x25519_secret_bytes(),
            &pk.to_x25519_public_bytes(),
            b"zone:default",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn id_public_key_helper_matches_keypair() {
        // Sanity: PublicKey constructed from hex roundtrips to the
        // same X25519 bytes as the original keypair.
        let kp = Keypair::from_seed(&[3u8; 32]);
        let pk_hex = kp.public_key().to_hex();
        let parsed = IdPublicKey::from_hex(&pk_hex).unwrap();
        assert_eq!(
            parsed.to_x25519_public_bytes(),
            kp.public_key().to_x25519_public_bytes()
        );
    }
}
