//! A secret sealed by one member for another (JI-01A7-0F).
//!
//! The sender wraps the plaintext under the pairwise KEK of their own
//! X25519 secret and the recipient's X25519 public key, both derived from
//! the Ed25519 identities ([`crate::pairwise`]). Only the two of them can
//! open it, and the recipient learns from the header who sealed it. The
//! `info` binds a seal to what it is for, so one made for one purpose
//! does not open as another.
//!
//! Layout, hex-encoded: the sender's 32-byte verify key, then
//! [`crate::wrap::wrap`] of the plaintext. The same layout as a zone-key
//! wrap ([`crate::zone::wrap_for_member`]), for any plaintext.

use crate::identity::{Keypair, PublicKey};
use crate::pairwise::pairwise_kek;
use crate::wrap;
use crate::Error;

/// Seal `plaintext` with the sender's identity seed for the holder of
/// `recipient`.
pub fn seal_for(
    sender_seed: &[u8; 32],
    recipient: &PublicKey,
    info: &[u8],
    plaintext: &[u8],
) -> String {
    let sender = Keypair::from_seed(sender_seed);
    let kek = pairwise_kek(
        &sender.to_x25519_secret_bytes(),
        &recipient.to_x25519_public_bytes(),
        info,
    );
    let inner = wrap::wrap(&kek, plaintext);
    let mut out = Vec::with_capacity(32 + inner.len());
    out.extend_from_slice(&sender.public_key().as_bytes());
    out.extend_from_slice(&inner);
    hex::encode(out)
}

/// The verify key of whoever sealed `sealed_hex`, as its header says. It
/// is proven only once [`open_from`] succeeds.
pub fn sealed_by(sealed_hex: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(sealed_hex).map_err(|e| Error::Auth(format!("invalid seal: {e}")))?;
    if bytes.len() < 32 {
        return Err(Error::Auth("seal too short to name its sender".into()));
    }
    PublicKey::from_hex(&hex::encode(&bytes[..32]))
}

/// Open what was sealed for the holder of `recipient_seed`, and say who
/// sealed it.
pub fn open_from(
    sealed_hex: &str,
    recipient_seed: &[u8; 32],
    info: &[u8],
) -> Result<(PublicKey, Vec<u8>), Error> {
    let sender = sealed_by(sealed_hex)?;
    let bytes = hex::decode(sealed_hex).map_err(|e| Error::Auth(format!("invalid seal: {e}")))?;
    let recipient = Keypair::from_seed(recipient_seed);
    let kek = pairwise_kek(
        &recipient.to_x25519_secret_bytes(),
        &sender.to_x25519_public_bytes(),
        info,
    );
    let plaintext = wrap::unwrap(&kek, &bytes[32..])?;
    Ok((sender, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_recipient_opens_it_and_learns_who_sealed_it() {
        let (alice, platform, other) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let recipient = Keypair::from_seed(&platform).public_key();
        let sealed = seal_for(
            &alice,
            &recipient,
            b"job-token:TST-JOB-0001-AA",
            b"joy_t_secret",
        );

        let (sender, plaintext) =
            open_from(&sealed, &platform, b"job-token:TST-JOB-0001-AA").unwrap();
        assert_eq!(plaintext, b"joy_t_secret");
        assert_eq!(
            sender.to_hex(),
            Keypair::from_seed(&alice).public_key().to_hex()
        );
        assert_eq!(sealed_by(&sealed).unwrap().to_hex(), sender.to_hex());

        // nobody else opens it, and not for another purpose
        assert!(open_from(&sealed, &other, b"job-token:TST-JOB-0001-AA").is_err());
        assert!(open_from(&sealed, &platform, b"job-token:TST-JOB-0002-BB").is_err());
    }

    #[test]
    fn a_seal_whose_sender_was_swapped_does_not_open() {
        let (alice, platform, mallory) = ([1u8; 32], [2u8; 32], [4u8; 32]);
        let recipient = Keypair::from_seed(&platform).public_key();
        let sealed = seal_for(&alice, &recipient, b"x", b"secret");
        let mut bytes = hex::decode(&sealed).unwrap();
        bytes[..32].copy_from_slice(&Keypair::from_seed(&mallory).public_key().as_bytes());
        assert!(open_from(&hex::encode(bytes), &platform, b"x").is_err());
        assert!(sealed_by("zz").is_err());
        assert!(sealed_by("00").is_err());
    }
}
