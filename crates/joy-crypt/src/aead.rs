//! AES-256-GCM authenticated encryption with associated data.
//!
//! `seal`/`open` are the low-level primitives that take an explicit nonce
//! and AAD. Callers that just want to wrap a key under a KEK without
//! managing nonces should use `wrap` instead.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::Error;

/// AES-256-GCM seal. Produces ciphertext || 16-byte auth tag.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Aead)
}

/// AES-256-GCM open. Expects ciphertext || 16-byte auth tag.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [9u8; 32]
    }
    fn nonce() -> [u8; 12] {
        [3u8; 12]
    }

    #[test]
    fn roundtrip() {
        let k = key();
        let n = nonce();
        let ct = seal(&k, &n, b"context", b"plaintext").unwrap();
        let pt = open(&k, &n, b"context", &ct).unwrap();
        assert_eq!(pt, b"plaintext");
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let k = key();
        let n = nonce();
        let ct = seal(&k, &n, b"", b"").unwrap();
        let pt = open(&k, &n, b"", &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let k = key();
        let n = nonce();
        let mut ct = seal(&k, &n, b"", b"plaintext").unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(open(&k, &n, b"", &ct).unwrap_err(), Error::Aead));
    }

    #[test]
    fn wrong_aad_rejected() {
        let k = key();
        let n = nonce();
        let ct = seal(&k, &n, b"context-a", b"plaintext").unwrap();
        assert!(matches!(
            open(&k, &n, b"context-b", &ct).unwrap_err(),
            Error::Aead
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let n = nonce();
        let ct = seal(&[1u8; 32], &n, b"", b"plaintext").unwrap();
        assert!(matches!(
            open(&[2u8; 32], &n, b"", &ct).unwrap_err(),
            Error::Aead
        ));
    }
}
