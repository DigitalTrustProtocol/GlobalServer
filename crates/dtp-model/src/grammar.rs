//! Token grammars shared by NIP-32009 and NIP-32014.

/// Byte limit for `c`, `l`, and `s` values.
pub const TOKEN_BYTE_LIMIT: usize = 128;
/// Unicode character limit for `content`.
pub const CONTENT_CHAR_LIMIT: usize = 1024;

fn is_segment_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')
}

fn is_segment_start(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9')
}

/// `[a-z0-9][a-z0-9._-]*`
pub fn is_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && is_segment_start(bytes[0])
        && bytes[1..].iter().all(|&b| is_segment_char(b))
}

/// `[a-z0-9][a-z0-9._-]*(:[a-z0-9][a-z0-9._-]*)*`
pub fn is_segmented_name(value: &str) -> bool {
    !value.is_empty() && value.split(':').all(is_name)
}

/// Canonical context: empty, or a segmented name within the byte limit.
pub fn is_canonical_context(context: &str) -> bool {
    context.is_empty() || (context.len() <= TOKEN_BYTE_LIMIT && is_segmented_name(context))
}

/// Canonical label: non-empty segmented name within the byte limit.
pub fn is_canonical_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= TOKEN_BYTE_LIMIT && is_segmented_name(label)
}

/// Canonical scope: non-empty, within the byte limit, already lowercase.
pub fn is_canonical_scope(scope: &str) -> bool {
    !scope.is_empty() && scope.len() <= TOKEN_BYTE_LIMIT && scope.to_lowercase() == scope
}

/// Canonical identifier class (`k`): a segmented name.
pub fn is_identifier_class(value: &str) -> bool {
    is_segmented_name(value)
}

/// `^\d+$`
pub fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// Parses a base-10 Unix-seconds tag value within the safe-integer range.
pub fn parse_unix_seconds(value: &str) -> Option<u64> {
    if !is_digits(value) {
        return None;
    }
    let parsed: u64 = value.parse().ok()?;
    (parsed <= crate::event::MAX_SAFE_INTEGER).then_some(parsed)
}

/// Canonical scope string for `d` material: unique values sorted and joined.
pub fn canonical_scope_string(scopes: &[String]) -> String {
    let mut unique: Vec<&str> = scopes.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    unique.join(",")
}

/// Context fallback chain: exact, each parent prefix, then global (`""`).
pub fn context_chain(context: &str) -> Vec<String> {
    if context.is_empty() {
        return vec![String::new()];
    }
    let segments: Vec<&str> = context.split(':').collect();
    let mut chain: Vec<String> = (1..=segments.len())
        .rev()
        .map(|len| segments[..len].join(":"))
        .collect();
    chain.push(String::new());
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_grammar() {
        assert!(is_canonical_context(""));
        assert!(is_canonical_context("identity"));
        assert!(is_canonical_context("security:access:frontdoor"));
        assert!(is_canonical_context("a.b_c-d:0"));
        assert!(!is_canonical_context("Identity"));
        assert!(!is_canonical_context("a::b"));
        assert!(!is_canonical_context(":a"));
        assert!(!is_canonical_context("-a"));
        assert!(!is_canonical_context("a b"));
        assert!(!is_canonical_context(&"a".repeat(129)));
        assert!(is_canonical_context(&"a".repeat(128)));
    }

    #[test]
    fn chain_order() {
        assert_eq!(
            context_chain("security:access:frontdoor"),
            vec![
                "security:access:frontdoor",
                "security:access",
                "security",
                ""
            ]
        );
        assert_eq!(context_chain(""), vec![""]);
    }

    #[test]
    fn scope_string_sorts_and_dedups() {
        let scopes = vec!["x.com".to_string(), "twitter.com".into(), "x.com".into()];
        assert_eq!(canonical_scope_string(&scopes), "twitter.com,x.com");
        assert_eq!(canonical_scope_string(&[]), "");
    }

    #[test]
    fn unix_seconds() {
        assert_eq!(parse_unix_seconds("0"), Some(0));
        assert_eq!(parse_unix_seconds("1700000000"), Some(1_700_000_000));
        assert_eq!(parse_unix_seconds("-1"), None);
        assert_eq!(parse_unix_seconds("1.5"), None);
        assert_eq!(parse_unix_seconds("9007199254740992"), None);
    }
}
