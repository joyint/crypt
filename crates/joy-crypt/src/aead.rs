//! AES-256-GCM authenticated encryption with associated data.
//!
//! Used for content encryption inside zones and for seed/zone-key
//! wrapping (via `wrap`). Tampering is detected on decrypt.
