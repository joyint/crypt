//! Ed25519 identity primitives.
//!
//! `Keypair` derives deterministically from a 32-byte seed (or a
//! `DerivedKey` from `kdf`), produces signatures, and exposes its raw
//! seed bytes for at-rest persistence by callers that own their own
//! storage policy. `PublicKey` is the verification half, hex-encoded
//! when stored alongside other project metadata.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::kdf::DerivedKey;
use crate::Error;

/// Ed25519 signing keypair. Private key is zeroed on drop (handled by
/// `ed25519-dalek`'s internal `Zeroize`).
pub struct Keypair {
    signing_key: SigningKey,
}

/// Ed25519 verification key. Stored in project.yaml as hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl Keypair {
    /// Create a keypair from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Create a keypair from derived key material (Argon2id output).
    pub fn from_derived_key(key: &DerivedKey) -> Self {
        Self::from_seed(key.as_bytes())
    }

    /// Generate a random keypair (for ephemeral session or one-time keys).
    pub fn from_random() -> Self {
        use rand::rngs::OsRng;
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Wrap an existing `SigningKey` (for callers that hold one already).
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self { signing_key: key }
    }

    /// Get the public key for this keypair.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing_key.verifying_key())
    }

    /// Sign a message and return the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    /// Extract the 32-byte seed for at-rest persistence. The caller is
    /// responsible for protecting the bytes (file permissions, encryption).
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Convert this Ed25519 signing key into an X25519 secret scalar
    /// (32 bytes, bit-clamped). Used by the pairwise wrap path so the
    /// same identity that signs Auth events also drives Crypt ECDH;
    /// no separate keypair is stored. The conversion follows the
    /// standard Ed25519-to-X25519 procedure: SHA-512 of the seed,
    /// take the first 32 bytes, apply X25519 bit clamping.
    pub fn to_x25519_secret_bytes(&self) -> [u8; 32] {
        let seed = self.signing_key.to_bytes();
        let hash = Sha512::digest(seed);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&hash[..32]);
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        secret
    }
}

impl PublicKey {
    /// Verify a signature against this public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = Signature::from_slice(signature).map_err(|_| Error::SignatureVerification)?;
        self.0
            .verify(message, &sig)
            .map_err(|_| Error::SignatureVerification)
    }

    /// Encode as hex string for storage.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidHex(e.to_string()))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| Error::InvalidLength {
            expected: 32,
            got: v.len(),
        })?;
        let key = VerifyingKey::from_bytes(&arr).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self(key))
    }

    /// Raw 32-byte form. Used when binding the public key into
    /// authenticated-data fields outside hex encoding.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert this Ed25519 verification key to its X25519 (Montgomery
    /// form) public counterpart. Pairs with
    /// `Keypair::to_x25519_secret_bytes` for ECDH on the same identity
    /// material. Returns 32 bytes suitable for `x25519_dalek::PublicKey`.
    pub fn to_x25519_public_bytes(&self) -> [u8; 32] {
        self.0.to_montgomery().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_argon2id, Salt};

    const TEST_PASSPHRASE: &str = "correct horse battery staple extra words";

    fn fixed_seed() -> [u8; 32] {
        [7u8; 32]
    }

    fn derived_keypair() -> Keypair {
        let salt =
            Salt::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        let key = derive_argon2id(TEST_PASSPHRASE, &salt).unwrap();
        Keypair::from_derived_key(&key)
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = fixed_seed();
        let a = Keypair::from_seed(&seed);
        let b = Keypair::from_seed(&seed);
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn from_derived_key_deterministic() {
        let kp1 = derived_keypair();
        let kp2 = derived_keypair();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn random_keypairs_differ() {
        let a = Keypair::from_random();
        let b = Keypair::from_random();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Keypair::from_seed(&fixed_seed());
        let sig = kp.sign(b"hello");
        kp.public_key().verify(b"hello", &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let kp = Keypair::from_seed(&fixed_seed());
        let sig = kp.sign(b"original");
        assert!(kp.public_key().verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_other_key() {
        let kp_a = Keypair::from_seed(&[1u8; 32]);
        let kp_b = Keypair::from_seed(&[2u8; 32]);
        let sig = kp_a.sign(b"hello");
        assert!(kp_b.public_key().verify(b"hello", &sig).is_err());
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let kp = Keypair::from_seed(&fixed_seed());
        let pk = kp.public_key();
        let parsed = PublicKey::from_hex(&pk.to_hex()).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn public_key_invalid_hex_rejected() {
        assert!(matches!(
            PublicKey::from_hex("zzzz").unwrap_err(),
            Error::InvalidHex(_)
        ));
    }

    #[test]
    fn public_key_invalid_length_rejected() {
        assert!(matches!(
            PublicKey::from_hex("00").unwrap_err(),
            Error::InvalidLength { expected: 32, .. }
        ));
    }

    #[test]
    fn seed_roundtrip_preserves_keypair() {
        let seed = fixed_seed();
        let kp = Keypair::from_seed(&seed);
        let extracted = kp.to_seed_bytes();
        let kp2 = Keypair::from_seed(&extracted);
        assert_eq!(kp.public_key(), kp2.public_key());
    }
}
