//! Keys: npub (NIP-19) encoding and a BIP-340 signer for the server key,
//! writers, and tests.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use k256::schnorr::SigningKey;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::event::Event;
use crate::hex32;

const NPUB_HRP: &str = "npub";

/// Decodes a bech32 `npub1…` (case-insensitive, surrounding whitespace
/// ignored) into lowercase hex. `None` if not a valid 32-byte npub.
pub fn decode_npub(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() < 5 || !trimmed[..5].eq_ignore_ascii_case("npub1") {
        return None;
    }
    // Bech32 allows an all-uppercase string; mixed case stays invalid.
    let normalized = if trimmed == trimmed.to_ascii_uppercase() {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed.to_string()
    };
    let checked = CheckedHrpstring::new::<Bech32>(&normalized).ok()?;
    if checked.hrp().as_str() != NPUB_HRP {
        return None;
    }
    let data: Vec<u8> = checked.byte_iter().collect();
    if data.len() != 32 {
        return None;
    }
    Some(hex::encode(data))
}

/// Encodes 64-hex into a lowercase `npub1…`.
pub fn encode_npub(pubkey_hex: &str) -> Option<String> {
    let bytes = hex32(pubkey_hex)?;
    let hrp = Hrp::parse(NPUB_HRP).ok()?;
    bech32::encode::<Bech32>(hrp, &bytes).ok()
}

/// A secp256k1 key pair used for BIP-340 signing.
#[derive(Clone)]
pub struct Keys {
    signing: SigningKey,
    pubkey: String,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("pubkey", &self.pubkey)
            .finish()
    }
}

impl Keys {
    /// Builds keys from a 32-byte secret.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Option<Keys> {
        let signing = SigningKey::from_bytes(secret).ok()?;
        let pubkey = hex::encode(signing.verifying_key().to_bytes());
        Some(Keys { signing, pubkey })
    }

    /// Builds keys from a 64-hex secret.
    pub fn from_secret_hex(secret: &str) -> Option<Keys> {
        let trimmed = secret.trim().to_ascii_lowercase();
        Keys::from_secret_bytes(&hex32(&trimmed)?)
    }

    /// Deterministic keys for tests: the secret is `sha256(seed)` (rehashed
    /// in the vanishing case that it is not a valid scalar).
    pub fn from_seed(seed: &str) -> Keys {
        let mut digest: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
        loop {
            if let Some(keys) = Keys::from_secret_bytes(&digest) {
                return keys;
            }
            digest = Sha256::digest(digest).into();
        }
    }

    /// Fresh random keys.
    pub fn generate() -> Keys {
        loop {
            let mut secret = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            if let Some(keys) = Keys::from_secret_bytes(&secret) {
                return keys;
            }
        }
    }

    /// Lowercase hex public key.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// Lowercase hex secret key (for writing key files).
    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    /// Signs a 32-byte message with BIP-340 (random auxiliary data).
    pub fn sign_raw(&self, msg: &[u8; 32]) -> String {
        let mut aux = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut aux);
        let sig = self
            .signing
            .sign_raw(msg, &aux)
            .expect("BIP-340 signing of a 32-byte message succeeds");
        hex::encode(sig.to_bytes())
    }

    /// Builds, hashes, and signs an event.
    pub fn sign_event(
        &self,
        created_at: u64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> Event {
        let id = Event::compute_id(&self.pubkey, created_at, kind, &tags, content);
        let msg = hex32(&id).expect("computed id is hex");
        let sig = self.sign_raw(&msg);
        Event {
            id,
            pubkey: self.pubkey.clone(),
            created_at,
            kind,
            tags,
            content: content.to_string(),
            sig,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npub_round_trip_and_nip19_vector() {
        // NIP-19 example.
        let hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
        assert_eq!(encode_npub(hex).as_deref(), Some(npub));
        assert_eq!(decode_npub(npub).as_deref(), Some(hex));
        assert_eq!(decode_npub(&npub.to_uppercase()).as_deref(), Some(hex));
        assert_eq!(decode_npub(&format!("  {npub} ")).as_deref(), Some(hex));
    }

    #[test]
    fn bad_npubs_are_rejected() {
        assert_eq!(decode_npub("npub1"), None);
        assert_eq!(
            decode_npub("nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"),
            None
        );
        // Flipped checksum character.
        assert_eq!(
            decode_npub("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7"),
            None
        );
    }

    #[test]
    fn seeded_keys_are_deterministic() {
        assert_eq!(Keys::from_seed("a").pubkey(), Keys::from_seed("a").pubkey());
        assert_ne!(Keys::from_seed("a").pubkey(), Keys::from_seed("b").pubkey());
        let keys = Keys::from_seed("a");
        let again = Keys::from_secret_hex(&keys.secret_hex()).unwrap();
        assert_eq!(keys.pubkey(), again.pubkey());
    }
}
