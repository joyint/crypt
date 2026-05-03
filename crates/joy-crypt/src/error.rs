//! Error type for joy-crypt primitives.
//!
//! Crypto failures map onto a small set of categories. Callers in joy-core
//! convert to their own error type at the boundary.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("invalid length: expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("invalid Ed25519 key")]
    InvalidPublicKey,

    #[error("signature verification failed")]
    SignatureVerification,

    #[error("Argon2id derivation failed: {0}")]
    Kdf(String),

    #[error("AEAD operation failed")]
    Aead,
}
