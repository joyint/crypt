//! Ed25519 identity primitives.
//!
//! Seed-to-keypair derivation, sign and verify operations. The same
//! keypair is used for Auth (signing actions) and Crypt (wrapping
//! per-member zone keys). joy-core/auth manages session storage and
//! token construction on top of these primitives.
