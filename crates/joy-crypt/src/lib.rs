//! joy-crypt: cryptographic primitives for Joy.
//!
//! Leaf crate. Owns Argon2id KDF, AES-256-GCM AEAD, Ed25519 sign/verify,
//! seed and zone-key wrapping, Job-bound session wraps, and secret
//! containers. No knowledge of the joy item or auth-token model; that
//! lives in joy-core.
//!
//! See ADR-039 §"Crate boundary and dependency direction" for the
//! decision that fixes joy-crypt as the leaf crate.

#![forbid(unsafe_code)]

pub mod aead;
pub mod identity;
pub mod kdf;
pub mod session_wrap;
pub mod wrap;
pub mod zone;
