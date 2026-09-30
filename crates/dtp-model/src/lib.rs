//! `dtp-model`: the protocol layer of `dtp-wot/1`.
//!
//! Parses and validates signed Nostr events of the kinds the resolver holds
//! (`32009`, `32014`, `10011`, NIP-09 kind `5`) and normalizes them into the
//! records the graph consumes (TrustGraph `wot-model.md` §2). It mirrors the
//! TypeScript reference in `AttentionX/src/lib/nostr`.

pub mod claim;
pub mod content;
pub mod deletion;
pub mod event;
pub mod grammar;
pub mod keys;
pub mod record;
pub mod scope;
pub mod score;
pub mod statement;
pub mod subject;

pub use claim::{ClaimRecord, parse_claim};
pub use deletion::{Deletion, DeletionTarget, parse_deletion};
pub use event::{Event, EventError};
pub use keys::{Keys, decode_npub, encode_npub};
pub use record::{EdgeRecord, RecordValue, ScoreMicro};
pub use scope::ScopeProfile;
pub use statement::{ValidationError, Verdict, validate_statement};
pub use subject::{Subject, SubjectType};

/// Kind `32009`: trust statement.
pub const KIND_TRUST: u32 = 32009;
/// Kind `32014`: rating statement.
pub const KIND_RATING: u32 = 32014;
/// Kind `10011`: NIP-39 identity claims.
pub const KIND_IDENTITY: u32 = 10011;
/// Kind `5`: NIP-09 deletion.
pub const KIND_DELETION: u32 = 5;
/// Kind `22242`: NIP-42 client authentication.
pub const KIND_AUTH: u32 = 22242;
/// Kind `13534`: NIP-43 membership list.
pub const KIND_MEMBERSHIP: u32 = 13534;
/// Kind `33534`: NIP-43 role definition.
pub const KIND_ROLE: u32 = 33534;

/// Model version reported in NIP-11 and `DTP info`.
pub const MODEL_VERSION: &str = "dtp-wot/1";
/// Corpus format this implementation reads.
pub const CORPUS_VERSION: &str = "dtp-wot-corpus/1";
/// Resolver protocol version.
pub const API_VERSION: &str = "v1";

/// Returns `true` for 64 lowercase hex characters.
pub fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// SHA-256 of a UTF-8 string as lowercase hex.
pub fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Decodes 64 lowercase hex characters into 32 bytes.
pub fn hex32(value: &str) -> Option<[u8; 32]> {
    if !is_hex64(value) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out).ok()?;
    Some(out)
}
