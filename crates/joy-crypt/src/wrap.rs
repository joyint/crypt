//! Seed and key wrapping under a KEK.
//!
//! `wrap(kek, plaintext)` generates a random 12-byte nonce, encrypts via
//! AES-256-GCM with empty AAD, and returns `nonce || ciphertext || tag`.
//! `unwrap` reads the nonce prefix and decrypts. Used for the wrapped-seed
//! Auth model (per ADR-039) and per-member zone-key wraps.

use rand::RngCore;

use crate::aead;
use crate::Error;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Wrap a plaintext blob under a KEK. Output layout: 12-byte nonce ||
/// ciphertext || 16-byte tag (the tag is appended by AES-GCM, so the total
/// length is `12 + plaintext.len() + 16`).
pub fn wrap(kek: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = aead::seal(kek, &nonce, &[], plaintext)
        .expect("AES-256-GCM seal with valid key never fails");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Unwrap a `wrap`ped blob. Verifies the auth tag and returns the
/// plaintext on success.
pub fn unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
    if wrapped.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::InvalidLength {
            expected: NONCE_LEN + TAG_LEN,
            got: wrapped.len(),
        });
    }
    let (nonce_bytes, ct) = wrapped.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("split_at(NONCE_LEN) yields NONCE_LEN bytes");
    aead::open(kek, &nonce, &[], ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> [u8; 32] {
        [11u8; 32]
    }

    #[test]
    fn roundtrip() {
        let k = kek();
        let pt = b"identity seed material";
        let w = wrap(&k, pt);
        let unwrapped = unwrap(&k, &w).unwrap();
        assert_eq!(unwrapped, pt);
    }

    #[test]
    fn nonce_is_random_each_call() {
        let k = kek();
        let a = wrap(&k, b"same plaintext");
        let b = wrap(&k, b"same plaintext");
        assert_ne!(a, b, "random nonce should produce distinct ciphertexts");
    }

    #[test]
    fn wrong_kek_rejected() {
        let pt = b"secret";
        let w = wrap(&[1u8; 32], pt);
        assert!(matches!(unwrap(&[2u8; 32], &w).unwrap_err(), Error::Aead));
    }

    #[test]
    fn truncated_wrap_rejected() {
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        assert!(matches!(
            unwrap(&kek(), &short).unwrap_err(),
            Error::InvalidLength { .. }
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let k = kek();
        let mut w = wrap(&k, b"secret");
        let last = w.len() - 1;
        w[last] ^= 0x01;
        assert!(matches!(unwrap(&k, &w).unwrap_err(), Error::Aead));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let k = kek();
        let w = wrap(&k, b"");
        let pt = unwrap(&k, &w).unwrap();
        assert!(pt.is_empty());
    }
}
