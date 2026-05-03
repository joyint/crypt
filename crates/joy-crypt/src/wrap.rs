//! Seed wrapping and unwrapping.
//!
//! Wraps the per-member identity seed under a passphrase-derived KEK
//! and a recovery-key-derived KEK (per ADR-039). Either wrap unlocks
//! the same seed, keeping the identity keypair stable across
//! passphrase rotation.
