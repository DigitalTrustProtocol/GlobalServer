//! NIP-01 events: shape, id hash, BIP-340 signature.

use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{hex32, is_hex64};

/// Largest integer JavaScript represents exactly (`Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A signed Nostr event with the seven NIP-01 fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// Why an event failed the NIP-01 checks.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    #[error("event does not have a valid Nostr event shape")]
    Shape,
    #[error("event id must be 64 lowercase hexadecimal characters")]
    IdFormat,
    #[error("event id does not match its serialized event hash")]
    IdMismatch,
    #[error("event signature is invalid")]
    Signature,
}

impl EventError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            EventError::Shape => "shape",
            EventError::IdFormat => "id-format",
            EventError::IdMismatch => "id-mismatch",
            EventError::Signature => "bad-sig",
        }
    }
}

impl Event {
    /// Parses one event from a JSON value, enforcing field types.
    pub fn from_value(value: &serde_json::Value) -> Result<Event, EventError> {
        serde_json::from_value(value.clone()).map_err(|_| EventError::Shape)
    }

    /// NIP-01 serialization `[0, pubkey, created_at, kind, tags, content]`.
    pub fn serialize_for_id(
        pubkey: &str,
        created_at: u64,
        kind: u32,
        tags: &[Vec<String>],
        content: &str,
    ) -> String {
        let value = serde_json::json!([0, pubkey, created_at, kind, tags, content]);
        serde_json::to_string(&value).expect("json array serializes")
    }

    /// Computes the NIP-01 event id (lowercase hex SHA-256).
    pub fn compute_id(
        pubkey: &str,
        created_at: u64,
        kind: u32,
        tags: &[Vec<String>],
        content: &str,
    ) -> String {
        let serialized = Self::serialize_for_id(pubkey, created_at, kind, tags, content);
        hex::encode(Sha256::digest(serialized.as_bytes()))
    }

    /// Shape checks beyond serde types (`validateEvent` in nostr-tools).
    pub fn check_shape(&self) -> Result<(), EventError> {
        if !is_hex64(&self.pubkey) || self.created_at > MAX_SAFE_INTEGER {
            return Err(EventError::Shape);
        }
        Ok(())
    }

    /// Verifies shape, id hash, and BIP-340 signature.
    pub fn verify(&self) -> Result<(), EventError> {
        self.check_shape()?;
        let id = hex32(&self.id).ok_or(EventError::IdFormat)?;
        let expected = Self::compute_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if expected != self.id {
            return Err(EventError::IdMismatch);
        }
        verify_signature(&self.pubkey, &id, &self.sig)
    }

    /// Tags whose first element equals `name`.
    pub fn tags_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Vec<String>> + 'a {
        self.tags
            .iter()
            .filter(move |tag| tag.first().map(String::as_str) == Some(name))
    }

    /// Serializes the event as a JSON value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("event serializes")
    }
}

/// Verifies a BIP-340 signature over a 32-byte message.
pub fn verify_signature(pubkey_hex: &str, msg: &[u8; 32], sig_hex: &str) -> Result<(), EventError> {
    let pubkey = hex32(pubkey_hex).ok_or(EventError::Signature)?;
    if sig_hex.len() != 128 {
        return Err(EventError::Signature);
    }
    let sig_bytes = hex::decode(sig_hex).map_err(|_| EventError::Signature)?;
    let key = VerifyingKey::from_bytes(&pubkey).map_err(|_| EventError::Signature)?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| EventError::Signature)?;
    key.verify_raw(msg, &sig).map_err(|_| EventError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    #[test]
    fn serialization_matches_nip01_escaping() {
        let s = Event::serialize_for_id(
            "ab",
            1,
            1,
            &[vec!["t".into(), "a\"b\n".into()]],
            "tab\there\u{1}",
        );
        assert_eq!(s, r#"[0,"ab",1,1,[["t","a\"b\n"]],"tab\there\u0001"]"#);
    }

    #[test]
    fn signed_event_verifies_and_tampering_fails() {
        let keys = Keys::from_seed("alice");
        let event = keys.sign_event(1_700_000_000, 1, vec![vec!["t".into(), "x".into()]], "hi");
        assert_eq!(event.verify(), Ok(()));

        let mut bad_id = event.clone();
        bad_id.content = "changed".into();
        assert_eq!(bad_id.verify(), Err(EventError::IdMismatch));

        let mut bad_sig = event.clone();
        let mut sig = bad_sig.sig.into_bytes();
        sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
        bad_sig.sig = String::from_utf8(sig).unwrap();
        assert_eq!(bad_sig.verify(), Err(EventError::Signature));

        let mut upper = event;
        upper.id = upper.id.to_uppercase();
        assert_eq!(upper.verify(), Err(EventError::IdFormat));
    }

    #[test]
    fn known_vector_verifies() {
        // BIP-340 test vector 1 (secret key 3), message 0x00..00 is not a NIP-01
        // id, so verify the raw signature path directly.
        let pk = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
        let msg = [0u8; 32];
        let sig = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0";
        assert_eq!(verify_signature(pk, &msg, sig), Ok(()));
    }
}
