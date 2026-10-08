// Copyright (c) 2026 Joydev GmbH (joydev.com)
// SPDX-License-Identifier: MIT

//! Per-(operator, AI) delegation key derivation.
//!
//! Each operator has one stable Ed25519 delegation keypair per AI member
//! they delegate to. The keypair is derived deterministically via HKDF
//! from the operator's identity seed, a per-(operator, AI)
//! `delegation_salt` recorded in `project.yaml`, and the (project, AI)
//! identifier used as the HKDF info parameter.
//!
//! The matching public key (`delegation_verifier`) is recorded once in
//! `project.yaml` under
//! `members.<operator>.ai_delegations.<ai-member>`. The private key is
//! re-derived in process memory whenever the operator enters their
//! passphrase, used for the signing or wrap operation, and discarded.
//! It is never persisted to disk; rotating the salt is the explicit
//! revocation handle.

use joy_crypt::kdf::{derive_hkdf_sha256, Salt};

/// Derive a 32-byte Ed25519 seed for a per-(operator, AI) delegation
/// key.
///
/// Inputs:
///   - `identity_seed`: the operator's 32-byte identity seed (the value
///     unwrapped from `seed_wrap_passphrase`, stable across passphrase
///     rotation).
///   - `salt`: the per-(operator, AI) `delegation_salt` recorded in
///     `project.yaml`.
///   - `project_id`: the canonical project id (acronym today).
///   - `ai_member`: the AI member's name (`claude`).
///
/// HKDF-SHA256 is used in extract-and-expand form. The `info` parameter
/// embeds project and member ids so the same `(seed, salt)` cannot be
/// replayed across (project, AI) pairs.
pub fn derive_delegation_seed(
    identity_seed: &[u8; 32],
    salt: &Salt,
    project_id: &str,
    ai_member: &str,
) -> [u8; 32] {
    let mut info = Vec::with_capacity(
        INFO_DOMAIN.len()
            + project_id.len()
            + 1
            + INFO_BEFORE_MEMBER.len()
            + ai_member.len()
            + INFO_AFTER_MEMBER.len(),
    );
    info.extend_from_slice(INFO_DOMAIN);
    info.extend_from_slice(project_id.as_bytes());
    info.push(b':');
    info.extend_from_slice(INFO_BEFORE_MEMBER);
    info.extend_from_slice(ai_member.as_bytes());
    info.extend_from_slice(INFO_AFTER_MEMBER);
    derive_hkdf_sha256(identity_seed, salt.as_bytes(), &info)
}

const INFO_DOMAIN: &[u8] = b"joy-delegation:";

/// The bytes that stand around the member's name in the derivation's
/// info. They are part of every delegation key ever derived: the public
/// halves of those keys stand in the projects out there, so these bytes
/// can never change, or every delegation would have to be made again.
/// They are a label of this derivation and nothing else. An AI member is
/// its name everywhere, here as well: what comes in is the name.
const INFO_BEFORE_MEMBER: &[u8] = b"ai:";
const INFO_AFTER_MEMBER: &[u8] = b"@joy";

#[cfg(test)]
mod tests {
    use super::*;
    use joy_crypt::kdf::generate_salt;

    const FIXED_SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn delegation_seed_is_deterministic() {
        let salt = generate_salt();
        let s1 = derive_delegation_seed(&FIXED_SEED, &salt, "JOY", "claude");
        let s2 = derive_delegation_seed(&FIXED_SEED, &salt, "JOY", "claude");
        assert_eq!(s1, s2);
    }

    /// The derivation is pinned: the key for one fixed input, as it was
    /// derived before AI members were known by their names. Whoever
    /// changes the info bytes makes every delegation out there useless,
    /// and this says so.
    #[test]
    fn delegation_seed_is_the_one_it_always_was() {
        let salt = joy_crypt::kdf::Salt::from_bytes([9u8; 32]);
        let seed = derive_delegation_seed(&FIXED_SEED, &salt, "JOY", "claude");
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "6c8a982e481d5db8e7504f71f408e5a05802b8f9ba9e4939f1d5d67e74cc5884"
        );
    }

    #[test]
    fn delegation_seed_changes_with_salt() {
        let s1 = derive_delegation_seed(&FIXED_SEED, &generate_salt(), "JOY", "claude");
        let s2 = derive_delegation_seed(&FIXED_SEED, &generate_salt(), "JOY", "claude");
        assert_ne!(s1, s2);
    }

    #[test]
    fn delegation_seed_is_domain_separated_by_project() {
        let salt = generate_salt();
        let s1 = derive_delegation_seed(&FIXED_SEED, &salt, "JOY", "claude");
        let s2 = derive_delegation_seed(&FIXED_SEED, &salt, "OTHER", "claude");
        assert_ne!(s1, s2);
    }

    #[test]
    fn delegation_seed_is_domain_separated_by_member() {
        let salt = generate_salt();
        let s1 = derive_delegation_seed(&FIXED_SEED, &salt, "JOY", "claude");
        let s2 = derive_delegation_seed(&FIXED_SEED, &salt, "JOY", "qwen");
        assert_ne!(s1, s2);
    }

    #[test]
    fn delegation_seed_changes_with_identity_key() {
        let salt = generate_salt();
        let seed_a = FIXED_SEED;
        let seed_b: [u8; 32] = [8u8; 32];
        let s1 = derive_delegation_seed(&seed_a, &salt, "JOY", "claude");
        let s2 = derive_delegation_seed(&seed_b, &salt, "JOY", "claude");
        assert_ne!(s1, s2);
    }
}
