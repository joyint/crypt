//! Zone keys and per-member wraps.
//!
//! Each Crypt zone has one AES-256-GCM key. Per-member wraps use the
//! member's Ed25519-derived public key. A member with a wrap for a
//! zone is Tier 1 for that zone; without, Tier 2 (see Crypt.md).
