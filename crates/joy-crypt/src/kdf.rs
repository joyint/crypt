//! Argon2id and HKDF-SHA256 key derivation.
//!
//! Argon2id derives 32 bytes of key material from a passphrase and a
//! per-(member, project) salt. Production parameters match Bitwarden
//! defaults: 64 MiB memory, 3 iterations, 4 lanes. Debug builds and the
//! `fast-kdf` feature use weaker parameters for fast tests; never enable
//! `fast-kdf` in release builds.
//!
//! HKDF-SHA256 is exposed as `derive_hkdf_sha256` for higher-level
//! derivations such as the per-(human, AI) delegation seed.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

/// Random 32-byte salt. Stored per-member in project.yaml as hex.
#[derive(Clone, Debug)]
pub struct Salt([u8; 32]);

impl Salt {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidHex(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| Error::InvalidLength {
                expected: 32,
                got: v.len(),
            })?;
        Ok(Self(arr))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Drop for Salt {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 32-byte derived key material. Zeroed on drop.
pub struct DerivedKey(Zeroizing<[u8; 32]>);

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a `DerivedKey` from raw bytes. Used by callers that already
    /// hold key material from another source (e.g. test fixtures).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Generate a random 32-byte salt.
pub fn generate_salt() -> Salt {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Salt(bytes)
}

/// Derive 32 bytes of key material from a passphrase and salt using Argon2id.
///
/// Production: m_cost=65536 (64 MiB), t_cost=3, p_cost=4, output=32 bytes.
/// Debug or `fast-kdf` feature: m_cost=256, t_cost=1, p_cost=1 (insecure).
pub fn derive_argon2id(passphrase: &str, salt: &Salt) -> Result<DerivedKey, Error> {
    #[cfg(any(feature = "fast-kdf", debug_assertions))]
    let params = Params::new(256, 1, 1, Some(32)).map_err(|e| Error::Kdf(e.to_string()))?;
    #[cfg(not(any(feature = "fast-kdf", debug_assertions)))]
    let params = Params::new(65536, 3, 4, Some(32)).map_err(|e| Error::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), output.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;

    Ok(DerivedKey(output))
}

/// HKDF-SHA256 in extract-and-expand form, returning 32 bytes.
///
/// `ikm` is input keying material, `salt` is HKDF salt, `info` provides
/// domain separation. Higher-level callers embed structured tags in `info`
/// to bind the output to a specific context.
pub fn derive_hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("HKDF-SHA256 expand to 32 bytes never fails");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSPHRASE: &str = "correct horse battery staple extra words";

    #[test]
    fn salt_is_random() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn salt_hex_roundtrip() {
        let salt = generate_salt();
        let hex = salt.to_hex();
        let parsed = Salt::from_hex(&hex).unwrap();
        assert_eq!(salt.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn salt_invalid_length_rejected() {
        assert!(matches!(
            Salt::from_hex("00").unwrap_err(),
            Error::InvalidLength { expected: 32, .. }
        ));
    }

    #[test]
    fn argon2_deterministic() {
        let salt =
            Salt::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let k1 = derive_argon2id(TEST_PASSPHRASE, &salt).unwrap();
        let k2 = derive_argon2id(TEST_PASSPHRASE, &salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn argon2_different_salt() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        let k1 = derive_argon2id(TEST_PASSPHRASE, &s1).unwrap();
        let k2 = derive_argon2id(TEST_PASSPHRASE, &s2).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn argon2_different_passphrase() {
        let salt = generate_salt();
        let k1 = derive_argon2id("one two three four five six", &salt).unwrap();
        let k2 = derive_argon2id("seven eight nine ten eleven twelve", &salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hkdf_deterministic() {
        let a = derive_hkdf_sha256(b"ikm", b"salt", b"info");
        let b = derive_hkdf_sha256(b"ikm", b"salt", b"info");
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_domain_separated_by_info() {
        let a = derive_hkdf_sha256(b"ikm", b"salt", b"context-a");
        let b = derive_hkdf_sha256(b"ikm", b"salt", b"context-b");
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_responds_to_salt() {
        let a = derive_hkdf_sha256(b"ikm", b"salt-a", b"info");
        let b = derive_hkdf_sha256(b"ikm", b"salt-b", b"info");
        assert_ne!(a, b);
    }
}
