// Copyright (c) 2026 Joydev GmbH (joydev.com)
// SPDX-License-Identifier: MIT

//! Delegation tokens and per-(operator, AI) delegation key derivation.
//!
//! This is the wasm-portable home of the token machinery (JI-0175-B0): it
//! depends only on `joy-crypt` and portable data crates, so the CLI, the
//! platform, and the browser all run the EXACT same token code — no
//! duplicated claims struct, no diverging signatures. `joy-core`
//! re-exports these types under `joy_core::auth::token` /
//! `joy_core::auth::delegation`, mapping [`TokenError`] into its own error.

pub mod delegation;
pub mod token;

pub use delegation::derive_delegation_seed;
pub use token::{
    create_token, decode_token, encode_token, is_token, validate_token, DelegationClaims,
    DelegationToken, TokenIssueParams, TokenSigningKeys, SCOPE_AUTH, SCOPE_CRYPT,
};

/// A token validation or decoding failure. String-carrying on purpose: the
/// messages are user-facing hints. `joy-core` maps this into its own
/// `JoyError::AuthFailed`.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TokenError(pub String);

impl TokenError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        TokenError(msg.into())
    }
}
