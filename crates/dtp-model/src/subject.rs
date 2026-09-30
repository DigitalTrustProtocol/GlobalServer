//! Subjects (`p` / `e` / `i`) and their validation
//! (`getTrustSubjectValidationError` in the TypeScript reference).

use serde::{Deserialize, Serialize};

use crate::grammar::is_digits;
use crate::is_hex64;

/// Primary subject tag name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SubjectType {
    #[serde(rename = "p")]
    P,
    #[serde(rename = "e")]
    E,
    #[serde(rename = "i")]
    I,
}

impl SubjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectType::P => "p",
            SubjectType::E => "e",
            SubjectType::I => "i",
        }
    }

    pub fn parse(value: &str) -> Option<SubjectType> {
        match value {
            "p" => Some(SubjectType::P),
            "e" => Some(SubjectType::E),
            "i" => Some(SubjectType::I),
            _ => None,
        }
    }
}

/// A wire subject `{ "type", "value" }`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subject {
    #[serde(rename = "type")]
    pub ty: SubjectType,
    pub value: String,
}

impl Subject {
    pub fn new(ty: SubjectType, value: impl Into<String>) -> Subject {
        Subject {
            ty,
            value: value.into(),
        }
    }

    /// Wire node id `"<type>:<value>"`.
    pub fn wire_id(&self) -> String {
        format!("{}:{}", self.ty.as_str(), self.value)
    }

    /// Parses a wire node id `"<type>:<value>"`.
    pub fn from_wire_id(id: &str) -> Option<Subject> {
        let (ty, value) = id.split_once(':')?;
        let ty = SubjectType::parse(ty)?;
        if value.is_empty() {
            return None;
        }
        Some(Subject::new(ty, value))
    }

    /// Graph node key (model §3, gap G5 fixed): see [`normalize_key`].
    pub fn node_key(&self) -> String {
        normalize_key(&self.value)
    }

    /// Validation error for a published subject, if any.
    pub fn validation_error(&self) -> Option<String> {
        match self.ty {
            SubjectType::P | SubjectType::E => (!is_hex64(&self.value)).then(|| {
                format!(
                    "{} subject must contain 64 lowercase hexadecimal characters",
                    self.ty.as_str()
                )
            }),
            SubjectType::I => identifier_error(&self.value),
        }
    }
}

/// Node key of a subject value: lowercased, except the case-sensitive parts
/// (gap G5): a `web:` URL keeps its path (protocol validation already made
/// scheme and host canonical) and a `nostr:addr:` identifier keeps its case.
pub fn normalize_key(value: &str) -> String {
    if value.starts_with("web:") {
        return value.to_string();
    }
    if let Some(rest) = value.strip_prefix("nostr:addr:") {
        let mut parts = rest.splitn(3, ':');
        if let (Some(kind), Some(pubkey), Some(identifier)) =
            (parts.next(), parts.next(), parts.next())
        {
            return format!(
                "nostr:addr:{}:{}:{identifier}",
                kind.to_lowercase(),
                pubkey.to_lowercase()
            );
        }
    }
    value.to_lowercase()
}

/// `user:id:<digits>` → the digits.
pub fn twitter_account_id(value: &str) -> Option<&str> {
    value.strip_prefix("user:id:").filter(|id| is_digits(id))
}

/// `post:id:<digits>` → the digits.
pub fn twitter_post_id(value: &str) -> Option<&str> {
    value.strip_prefix("post:id:").filter(|id| is_digits(id))
}

/// Canonical `web:` URL (absolute http(s), no fragment, default port dropped).
pub fn canonicalize_web_url(raw: &str) -> Result<String, String> {
    let mut url =
        url::Url::parse(raw).map_err(|_| "Web subject must contain an absolute URL".to_string())?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err("Web subject URL must use http or https".into());
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

fn identifier_error(value: &str) -> Option<String> {
    if twitter_account_id(value).is_some() || twitter_post_id(value).is_some() {
        return None;
    }
    if value.starts_with("ext:twitter")
        && matches!(value.as_bytes().get(11), Some(b'.' | b'_' | b':'))
        || value.starts_with("ext:x") && matches!(value.as_bytes().get(5), Some(b'.' | b'_' | b':'))
    {
        return Some("Kind 32009 subjects must not use ext:twitter_* or ext:x:* forms".into());
    }
    if value.starts_with("user:id:") {
        return Some("user:id subject must end in decimal digits".into());
    }
    if value.starts_with("post:id:") {
        return Some("post:id subject must end in decimal digits".into());
    }
    if let Some(hash) = value.strip_prefix("hash:") {
        return (!is_hex64(hash))
            .then(|| "Hash subject must contain 64 lowercase hexadecimal characters".into());
    }
    if let Some(raw) = value.strip_prefix("web:") {
        return match canonicalize_web_url(raw) {
            Ok(canonical) if canonical == raw => None,
            Ok(_) => Some("Web subject URL is not canonical".into()),
            Err(err) => Some(err),
        };
    }
    for prefix in ["nostr:profile:", "nostr:pubkey:"] {
        if let Some(hex) = value.strip_prefix(prefix)
            && is_hex64(hex)
        {
            return None;
        }
    }
    if let Some(addr) = value.strip_prefix("nostr:addr:") {
        let mut parts = addr.splitn(3, ':');
        let kind = parts.next().unwrap_or("");
        let pubkey = parts.next().unwrap_or("");
        let has_rest = parts.next().is_some();
        let kind_ok = (kind == "0" || (is_digits(kind) && !kind.starts_with('0')))
            && kind
                .parse::<u64>()
                .is_ok_and(|k| k <= crate::event::MAX_SAFE_INTEGER);
        if kind_ok && is_hex64(pubkey) && has_rest {
            return None;
        }
        return Some(
            "Nostr address subject must contain a canonical kind:pubkey:identifier coordinate"
                .into(),
        );
    }
    Some("Identifier subject must be a normalized typed identifier".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i(value: &str) -> Option<String> {
        Subject::new(SubjectType::I, value).validation_error()
    }

    #[test]
    fn identifier_subjects() {
        assert_eq!(i("user:id:11348282"), None);
        assert_eq!(i("post:id:2080659774136291424"), None);
        assert!(i("user:id:abc").is_some());
        assert!(i("post:id:").is_some());
        assert!(i("ext:twitter_id:1").is_some());
        assert!(i("ext:x:1").is_some());
        assert_eq!(i(&format!("hash:{}", "a".repeat(64))), None);
        assert!(i("hash:xyz").is_some());
        assert_eq!(i("web:https://example.com/path"), None);
        assert!(i("web:https://Example.com/path").is_some());
        assert!(i("web:https://example.com:443/path").is_some());
        assert!(i("web:ftp://example.com/").is_some());
        assert_eq!(i(&format!("nostr:pubkey:{}", "b".repeat(64))), None);
        assert_eq!(
            i(&format!("nostr:addr:30023:{}:slug", "b".repeat(64))),
            None
        );
        assert_eq!(i(&format!("nostr:addr:30023:{}:", "b".repeat(64))), None);
        assert!(i(&format!("nostr:addr:01:{}:x", "b".repeat(64))).is_some());
        assert!(i("something:else").is_some());
    }

    #[test]
    fn hex_subjects() {
        assert_eq!(
            Subject::new(SubjectType::P, "ab".repeat(32)).validation_error(),
            None
        );
        assert!(
            Subject::new(SubjectType::P, "AB".repeat(32))
                .validation_error()
                .is_some()
        );
        assert!(
            Subject::new(SubjectType::E, "ab")
                .validation_error()
                .is_some()
        );
    }

    #[test]
    fn wire_ids() {
        let s = Subject::from_wire_id("i:user:id:42").unwrap();
        assert_eq!(s.ty, SubjectType::I);
        assert_eq!(s.value, "user:id:42");
        assert_eq!(s.wire_id(), "i:user:id:42");
        assert!(Subject::from_wire_id("x:1").is_none());
        assert!(Subject::from_wire_id("p:").is_none());
    }
}
