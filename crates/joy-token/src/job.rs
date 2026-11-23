// Copyright (c) 2026 Joydev GmbH (joydev.com)
// SPDX-License-Identifier: MIT

//! The token of one job, issued and sealed (JI-01A7-0F).
//!
//! A person who puts a job to work issues a delegation token for the
//! job's AI assignee: valid [`DAYS`] days, for this one job, with their
//! grant as it stands. It is sealed for the platform that runs the job
//! ([`joy_crypt::sealed`]), so that platform alone reads it.
//!
//! What goes into it is a [`JobTokenRequest`], which the host that knows
//! the project builds; what makes it is here, so the CLI, the desktop
//! and the browser issue the same token with the same code. Only the
//! person's seed is added, and it never leaves the call.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use joy_crypt::identity::{Keypair, PublicKey};
use joy_crypt::kdf::Salt;

use crate::delegation::derive_delegation_seed;
use crate::token::{create_token, encode_token, TokenIssueParams, TokenSigningKeys};
use crate::TokenError;

/// How long a job's token holds.
pub const DAYS: i64 = 7;

/// Everything a job's token says, as the project stands: who it is for,
/// in whose name, for which job, and the platform it is sealed for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobTokenRequest {
    /// The job's AI assignee.
    pub ai_member: String,
    /// The person who issues it, by their key in the project.
    pub opener: String,
    pub project_id: String,
    /// The salt and the public key of the opener's delegation to the
    /// assignee, as their member entry records them.
    pub delegation_salt: String,
    pub delegation_verifier: String,
    /// What the opener allows the assignee right now, as a token names
    /// it ([`crate::token::grant_scope`]).
    pub grant: String,
    pub job: String,
    /// The platform the job runs on, by its domain, and its public key.
    pub platform: String,
    pub platform_key: String,
}

/// A job's token, sealed, with the one thing about it that is said in
/// clear next to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedJobToken {
    pub expires: DateTime<Utc>,
    /// Hex of the seal ([`joy_crypt::sealed::seal_for`]).
    pub sealed: String,
}

/// What binds the seal to this job of this project.
pub fn seal_info(project_id: &str, job: &str) -> Vec<u8> {
    format!("joy-job-token|{project_id}|{job}").into_bytes()
}

/// Issue the token `request` describes with the opener's identity seed
/// and seal it for the platform.
///
/// Refused when the seed does not derive the delegation the request
/// names: the delegation was rotated, or the seed is somebody else's.
pub fn issue(
    opener_seed: &[u8; 32],
    request: &JobTokenRequest,
) -> Result<SealedJobToken, TokenError> {
    let salt = Salt::from_hex(&request.delegation_salt)
        .map_err(|e| TokenError::new(format!("the delegation's salt cannot be read: {e}")))?;
    let delegation_seed =
        derive_delegation_seed(opener_seed, &salt, &request.project_id, &request.ai_member);
    let delegation = Keypair::from_seed(&delegation_seed);
    if delegation.public_key().to_hex() != request.delegation_verifier {
        return Err(TokenError::new(format!(
            "your delegation to {} does not match your key any more",
            request.ai_member
        )));
    }
    let platform_key = PublicKey::from_hex(&request.platform_key)
        .map_err(|e| TokenError::new(format!("the platform's key cannot be read: {e}")))?;
    let token = create_token(
        TokenSigningKeys {
            delegator: &Keypair::from_seed(opener_seed),
            delegation: &delegation,
            delegation_seed: &delegation_seed,
        },
        TokenIssueParams {
            ai_member: &request.ai_member,
            human: &request.opener,
            project_id: &request.project_id,
            ttl: Some(Duration::days(DAYS)),
            grant: Some(&request.grant),
            job: Some(&request.job),
        },
    );
    let expires = token
        .claims
        .expires
        .unwrap_or_else(|| Utc::now() + Duration::days(DAYS));
    Ok(SealedJobToken {
        expires,
        sealed: joy_crypt::sealed::seal_for(
            opener_seed,
            &platform_key,
            &seal_info(&request.project_id, &request.job),
            encode_token(&token).as_bytes(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{decode_token, grant_scope, job_scope, validate_token};
    use joy_crypt::kdf::generate_salt;

    const OPENER: [u8; 32] = [1u8; 32];
    const PLATFORM: [u8; 32] = [9u8; 32];

    fn request() -> JobTokenRequest {
        let salt = generate_salt();
        let seed = derive_delegation_seed(&OPENER, &salt, "TST", "claude");
        JobTokenRequest {
            ai_member: "claude".into(),
            opener: "founder@example.com".into(),
            project_id: "TST".into(),
            delegation_salt: salt.to_hex(),
            delegation_verifier: Keypair::from_seed(&seed).public_key().to_hex(),
            grant: "none".into(),
            job: "TST-JOB-0001-AA".into(),
            platform: "app.example.com".into(),
            platform_key: Keypair::from_seed(&PLATFORM).public_key().to_hex(),
        }
    }

    #[test]
    fn the_platform_opens_a_token_for_this_job_signed_by_the_opener() {
        let request = request();
        let issued = issue(&OPENER, &request).unwrap();
        let hours = (issued.expires - Utc::now()).num_hours();
        assert!((DAYS * 24 - 1..=DAYS * 24).contains(&hours), "{hours}");

        let (sealed_by, plain) = joy_crypt::sealed::open_from(
            &issued.sealed,
            &PLATFORM,
            &seal_info("TST", "TST-JOB-0001-AA"),
        )
        .unwrap();
        let opener_key = Keypair::from_seed(&OPENER).public_key();
        assert_eq!(sealed_by.to_hex(), opener_key.to_hex());
        let token = decode_token(std::str::from_utf8(&plain).unwrap()).unwrap();
        let delegation = PublicKey::from_hex(&request.delegation_verifier).unwrap();
        let claims = validate_token(&token, &opener_key, &delegation, "TST").unwrap();
        assert_eq!(job_scope(&claims), Some("TST-JOB-0001-AA"));
        assert_eq!(grant_scope(&claims), Some("none"));
        assert_eq!(claims.ai_member, "claude");
        assert_eq!(claims.delegated_by, "founder@example.com");
        assert_eq!(claims.expires, Some(issued.expires));
    }

    #[test]
    fn a_seed_that_is_not_the_delegations_issues_nothing() {
        let err = issue(&[5u8; 32], &request()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "your delegation to claude does not match your key any more"
        );
        let mut bad = request();
        bad.platform_key = "zz".into();
        assert!(issue(&OPENER, &bad).is_err());
    }
}
