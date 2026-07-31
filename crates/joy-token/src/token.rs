// Copyright (c) 2026 Joydev GmbH (joydev.com)
// SPDX-License-Identifier: MIT

//! AI delegation tokens with dual signatures (ADR-023, refined by ADR-033 and
//! ADR-041).
//!
//! Each token carries two Ed25519 signatures:
//! 1. Delegator signature (human's identity key) — proves authorization
//! 2. Binding signature (stable delegation key per (human, AI)) — binds to
//!    the public key recorded in `project.yaml` under
//!    `members[<human>].ai_delegations[<ai-member>].delegation_verifier`.
//!
//! Tokens carry a `scopes` claim (ADR-041 §3). The default `["auth"]` lets
//! the AI run joy commands as the AI member. With `--crypt` (`["auth",
//! "crypt"]`) the token additionally embeds the delegation private key as
//! a 32-byte Ed25519 seed so the AI can unwrap zone keys for the duration
//! of the token's TTL.
//!
//! Tokens are passed via `--token` flag or `JOY_TOKEN` env var to `joy auth`.
use chrono::{DateTime, Duration, Utc};
use joy_crypt::identity::{Keypair as IdentityKeypair, PublicKey};
use serde::{Deserialize, Serialize};

use crate::TokenError;

/// Token prefix for visual identification.
const TOKEN_PREFIX: &str = "joy_t_";

/// Default scope set when a token's claims omit the field (back-compat).
fn default_scopes() -> Vec<String> {
    vec!["auth".to_string()]
}

/// Scope value indicating the token additionally carries the delegation
/// private key for Crypt unwrap (ADR-041).
pub const SCOPE_CRYPT: &str = "crypt";
/// Scope value for ordinary AI command authentication (default).
pub const SCOPE_AUTH: &str = "auth";

/// Claims encoded in a delegation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationClaims {
    /// Unique identifier for this specific token (UUID v4). Used to detect
    /// replay: once a token has been redeemed, subsequent redemption
    /// attempts for the same `token_id` are rejected (ADR-033).
    pub token_id: String,
    pub ai_member: String,
    pub delegated_by: String,
    pub project_id: String,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    /// Capability scopes for this token, always `["auth", "crypt"]`.
    /// A delegation is not divisible: the AI acts with the key it was
    /// given. The claim stays on the wire because older verifiers still
    /// look for it, and unknown scopes are preserved so a newer
    /// vocabulary does not break an older reader.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

/// A delegation token with dual signatures.
#[derive(Debug, Serialize, Deserialize)]
pub struct DelegationToken {
    pub claims: DelegationClaims,
    /// Hex-encoded Ed25519 signature by the delegating human's key.
    pub delegator_signature: String,
    /// Hex-encoded Ed25519 signature by the stable delegation key.
    pub binding_signature: String,
    /// Hex-encoded public key of the delegation keypair. Redundant with the
    /// value recorded in `project.yaml` under `ai_delegations`; kept as an
    /// aid for debugging and for error messages pointing at a mismatch.
    pub delegation_public_key: String,
    /// Hex-encoded 32-byte Ed25519 seed for the delegation keypair. Present
    /// only on tokens with `crypt` scope; lets the AI re-derive the
    /// delegation keypair to unwrap zone keys (ADR-041 §2). Never persisted
    /// on the AI's disk; it travels in the token string and lives in the
    /// `JOY_SESSION` env var while a session is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_private_key: Option<String>,
}

/// Cryptographic material used to sign a delegation token.
pub struct TokenSigningKeys<'a> {
    /// Human's identity keypair, produces the delegator signature.
    pub delegator: &'a IdentityKeypair,
    /// Stable per-(human, AI) delegation keypair, produces the binding
    /// signature. The matching public key must already be recorded in
    /// `project.yaml`.
    pub delegation: &'a IdentityKeypair,
    /// 32-byte Ed25519 seed of the delegation keypair. It rides in the
    /// token: a delegation IS the key the AI acts with, for chats and
    /// zones alike.
    pub delegation_seed: &'a [u8; 32],
}

/// Identity and policy fields for a token issuance.
pub struct TokenIssueParams<'a> {
    pub ai_member: &'a str,
    pub human: &'a str,
    pub project_id: &'a str,
    pub ttl: Option<Duration>,
}

/// Create a delegation token with dual signatures.
///
/// The token carries the delegation seed. Delegating means the AI acts
/// with that identity: it reads the chats it is in and unwraps the zones
/// its delegator granted, with the one key it was given. A token that
/// only authenticates would be an identity that cannot do anything.
pub fn create_token(keys: TokenSigningKeys<'_>, params: TokenIssueParams<'_>) -> DelegationToken {
    let now = Utc::now();
    let scopes = vec![SCOPE_AUTH.to_string(), SCOPE_CRYPT.to_string()];
    let claims = DelegationClaims {
        token_id: uuid::Uuid::new_v4().to_string(),
        ai_member: params.ai_member.to_string(),
        delegated_by: params.human.to_string(),
        project_id: params.project_id.to_string(),
        created: now,
        expires: params.ttl.map(|d| now + d),
        scopes,
    };
    let claims_json = serde_json::to_string(&claims).expect("claims serialize");

    let delegator_sig = keys.delegator.sign(claims_json.as_bytes());
    let binding_sig = keys.delegation.sign(claims_json.as_bytes());

    let delegation_private_key = Some(hex::encode(keys.delegation_seed));

    DelegationToken {
        claims,
        delegator_signature: hex::encode(delegator_sig),
        binding_signature: hex::encode(binding_sig),
        delegation_public_key: keys.delegation.public_key().to_hex(),
        delegation_private_key,
    }
}

/// Validate a delegation token against the delegator's identity key and the
/// stable delegation key recorded in `project.yaml`.
pub fn validate_token(
    token: &DelegationToken,
    delegator_pk: &PublicKey,
    delegation_pk: &PublicKey,
    project_id: &str,
) -> Result<DelegationClaims, TokenError> {
    if token.claims.project_id != project_id {
        return Err(TokenError::new("token belongs to a different project"));
    }

    if let Some(expires) = token.claims.expires {
        if Utc::now() > expires {
            return Err(TokenError::new(format!(
                "Token expired (issued {}, expired {}). \
                 Ask the human to issue a new one with: joy auth token add {}",
                token.claims.created.format("%Y-%m-%d %H:%M UTC"),
                expires.format("%Y-%m-%d %H:%M UTC"),
                token.claims.ai_member
            )));
        }
    }

    let claims_json = serde_json::to_string(&token.claims).expect("claims serialize");

    let delegator_sig =
        hex::decode(&token.delegator_signature).map_err(|e| TokenError::new(format!("{e}")))?;
    delegator_pk
        .verify(claims_json.as_bytes(), &delegator_sig)
        .map_err(|e| TokenError::new(format!("delegator signature: {e}")))?;

    let binding_sig =
        hex::decode(&token.binding_signature).map_err(|e| TokenError::new(format!("{e}")))?;
    delegation_pk
        .verify(claims_json.as_bytes(), &binding_sig)
        .map_err(|e| TokenError::new(format!("binding signature: {e}")))?;

    Ok(token.claims.clone())
}

/// Encode a token as a portable string (`joy_t_<base64>`).
pub fn encode_token(token: &DelegationToken) -> String {
    let json = serde_json::to_string(token).expect("token serialize");
    let encoded = base64_encode(json.as_bytes());
    format!("{TOKEN_PREFIX}{encoded}")
}

/// Decode a token from its portable string representation.
///
/// Whitespace (spaces, newlines, tabs, CRs) is stripped before the
/// base64 stage so a token that survived an over-eager chat client
/// line-wrap still decodes. base64 and JSON errors are rewrapped in
/// a hint that names the most common real cause, namely a truncation
/// from a wrapped paste, so the operator (or an AI tool) knows to
/// re-paste rather than retry with new guesses.
pub fn decode_token(s: &str) -> Result<DelegationToken, TokenError> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    // Strip a single layer of surrounding `"` or `'` quotes. The
    // `joy auth token add` output wraps the token in double quotes
    // so chat clients treat it as one atomic string instead of
    // word-splitting on visual line wraps. Callers that re-paste
    // the quoted form into `joy auth --token` get it accepted
    // verbatim.
    let trimmed = cleaned
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| {
            cleaned
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
        })
        .unwrap_or(&cleaned);
    let data = trimmed
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| TokenError::new("invalid token format (missing joy_t_ prefix)"))?;
    let json = base64_decode(data).map_err(|e| wrap_decode_error(&e.to_string()))?;
    let token: DelegationToken =
        serde_json::from_slice(&json).map_err(|e| wrap_decode_error(&format!("{e}")))?;
    Ok(token)
}

fn wrap_decode_error(detail: &str) -> TokenError {
    TokenError::new(format!(
        "token decode failed: {detail}. \
         A delegation token is a single base64 line. If this was forwarded \
         through a chat tool, the visual line wrap may have hidden a \
         truncation: re-read the operator's original message in full, strip \
         all whitespace, and retry before asking the operator to paste it \
         again."
    ))
}

/// Check if a string looks like a delegation token (has the `joy_t_` prefix).
pub fn is_token(s: &str) -> bool {
    s.starts_with(TOKEN_PREFIX)
}

fn base64_encode(data: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, TokenError> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(s).map_err(|e| TokenError::new(format!("base64 decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use joy_crypt::kdf::{derive_argon2id as derive_key, Salt};

    const TEST_PASSPHRASE: &str = "correct horse battery staple extra words";

    fn test_keypair() -> (IdentityKeypair, PublicKey) {
        let salt =
            Salt::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let key = derive_key(TEST_PASSPHRASE, &salt).unwrap();
        let kp = IdentityKeypair::from_derived_key(&key);
        let pk = kp.public_key();
        (kp, pk)
    }

    fn fresh_delegation() -> ([u8; 32], IdentityKeypair, PublicKey) {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let kp = IdentityKeypair::from_seed(&seed);
        let pk = kp.public_key();
        (seed, kp, pk)
    }

    fn make_token(
        delegator: &IdentityKeypair,
        delegation: &IdentityKeypair,
        seed: &[u8; 32],
        ttl: Option<Duration>,
    ) -> DelegationToken {
        create_token(
            TokenSigningKeys {
                delegator,
                delegation,
                delegation_seed: seed,
            },
            TokenIssueParams {
                ai_member: "ai:claude@joy",
                human: "human@example.com",
                project_id: "TST",
                ttl,
            },
        )
    }

    #[test]
    fn create_and_validate_token() {
        let (delegator, delegator_pk) = test_keypair();
        let (seed, delegation, delegation_pk) = fresh_delegation();
        let token = make_token(&delegator, &delegation, &seed, None);
        let claims = validate_token(&token, &delegator_pk, &delegation_pk, "TST").unwrap();
        assert_eq!(claims.ai_member, "ai:claude@joy");
        assert_eq!(claims.delegated_by, "human@example.com");
        assert_eq!(token.delegation_public_key, delegation_pk.to_hex());
    }

    #[test]
    fn a_delegation_carries_the_key_it_delegates() {
        // One key, one delegation: the AI reads its chats and unwraps
        // the zones its delegator granted with the same key it signs
        // with. There is no half delegation that can only say hello.
        let (delegator, _) = test_keypair();
        let (seed, delegation, _) = fresh_delegation();
        let token = make_token(&delegator, &delegation, &seed, None);
        assert_eq!(token.delegation_private_key, Some(hex::encode(seed)));
    }

    #[test]
    fn expired_token_rejected() {
        let (delegator, delegator_pk) = test_keypair();
        let (seed, delegation, delegation_pk) = fresh_delegation();
        let token = make_token(&delegator, &delegation, &seed, Some(Duration::hours(-1)));
        assert!(validate_token(&token, &delegator_pk, &delegation_pk, "TST").is_err());
    }

    #[test]
    fn wrong_project_rejected() {
        let (delegator, delegator_pk) = test_keypair();
        let (seed, delegation, delegation_pk) = fresh_delegation();
        let token = make_token(&delegator, &delegation, &seed, None);
        assert!(validate_token(&token, &delegator_pk, &delegation_pk, "OTHER").is_err());
    }

    #[test]
    fn tampered_claims_rejected() {
        let (delegator, delegator_pk) = test_keypair();
        let (seed, delegation, delegation_pk) = fresh_delegation();
        let mut token = make_token(&delegator, &delegation, &seed, None);
        token.claims.ai_member = "ai:evil@joy".to_string();
        assert!(validate_token(&token, &delegator_pk, &delegation_pk, "TST").is_err());
    }

    #[test]
    fn wrong_delegator_key_rejected() {
        let (_, delegator_pk) = test_keypair();
        let (seed, delegation, delegation_pk) = fresh_delegation();
        let (other, _) = fresh_delegation_kp();
        let token = make_token(&other, &delegation, &seed, None);
        assert!(validate_token(&token, &delegator_pk, &delegation_pk, "TST").is_err());
    }

    #[test]
    fn wrong_delegation_key_rejected() {
        let (delegator, delegator_pk) = test_keypair();
        let (seed, _, delegation_pk) = fresh_delegation();
        let (other, _) = fresh_delegation_kp();
        let token = make_token(&delegator, &other, &seed, None);
        assert!(validate_token(&token, &delegator_pk, &delegation_pk, "TST").is_err());
    }

    fn fresh_delegation_kp() -> (IdentityKeypair, PublicKey) {
        let (_, kp, pk) = fresh_delegation();
        (kp, pk)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (delegator, _) = test_keypair();
        let (seed, delegation, _) = fresh_delegation();
        let token = make_token(&delegator, &delegation, &seed, None);
        let encoded = encode_token(&token);
        assert!(is_token(&encoded));
        let decoded = decode_token(&encoded).unwrap();
        assert_eq!(decoded.claims.token_id, token.claims.token_id);
        assert_eq!(decoded.delegation_private_key, token.delegation_private_key);
    }

    #[test]
    fn invalid_prefix_rejected() {
        assert!(decode_token("not-a-token").is_err());
    }

    #[test]
    fn decode_tolerates_embedded_whitespace() {
        let (delegator, _) = test_keypair();
        let (seed, delegation, _) = fresh_delegation();
        let token = make_token(&delegator, &delegation, &seed, None);
        let encoded = encode_token(&token);
        let wrapped = format!("{}\n  {}", &encoded[..20], &encoded[20..]);
        assert_eq!(
            decode_token(&wrapped).unwrap().claims.token_id,
            token.claims.token_id
        );
    }

    #[test]
    fn decode_accepts_double_quoted_token() {
        let (delegator, _) = test_keypair();
        let (seed, delegation, _) = fresh_delegation();
        let token = make_token(&delegator, &delegation, &seed, None);
        let encoded = encode_token(&token);
        assert!(decode_token(&format!("\"{encoded}\"")).is_ok());
    }
}
