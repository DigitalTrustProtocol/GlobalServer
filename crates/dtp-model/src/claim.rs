//! NIP-39 kind `10011` identity claims (wot-model §2.6).
//! Port of `validateKind10011TwitterIdentity`.

use crate::event::Event;
use crate::grammar::is_digits;
use crate::{KIND_IDENTITY, ValidationError};

/// The claim carried by a signed kind `10011` winner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimRecord {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    /// `twitter_id` digits when the event carries a valid X claim; `None`
    /// for a valid event without a claim (revoked, other providers only, or
    /// malformed twitter tags — "treated as none").
    pub twitter_id: Option<String>,
}

fn is_canonical_handle(handle: &str) -> bool {
    (1..=15).contains(&handle.len())
        && handle
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn proof_hint_matches(hint: Option<&String>, post_id: &str) -> bool {
    hint.is_some_and(|h| *h == format!("post:id:{post_id}"))
}

/// Extracts the X claim from the twitter / twitter_id `i` tags, or the
/// validation errors of those tags.
pub fn twitter_claim(event: &Event) -> Result<Option<String>, Vec<ValidationError>> {
    let is_twitter = |t: &&Vec<String>| {
        t.first().map(String::as_str) == Some("i")
            && t.get(1)
                .is_some_and(|v| v.starts_with("twitter:") || v.starts_with("twitter_id:"))
    };
    if !event.tags.iter().any(|t| is_twitter(&t)) {
        return Ok(None);
    }
    let handle_tags: Vec<&Vec<String>> = event
        .tags_named("i")
        .filter(|t| t.get(1).is_some_and(|v| v.starts_with("twitter:")))
        .collect();
    let id_tags: Vec<&Vec<String>> = event
        .tags_named("i")
        .filter(|t| t.get(1).is_some_and(|v| v.starts_with("twitter_id:")))
        .collect();
    let mut errors = Vec::new();
    let err = |code, msg: &str| ValidationError {
        code,
        message: msg.to_string(),
    };
    if handle_tags.len() != 1 || !(2..=4).contains(&handle_tags[0].len()) {
        errors.push(err(
            "twitter-tag",
            "Event must contain exactly one twitter i tag",
        ));
    }
    if id_tags.len() != 1 || !(2..=4).contains(&id_tags[0].len()) {
        errors.push(err(
            "twitter-id-tag",
            "Event must contain exactly one twitter_id i tag",
        ));
    }
    let handle = handle_tags
        .first()
        .and_then(|t| t[1].strip_prefix("twitter:"))
        .unwrap_or("");
    let twitter_id = id_tags
        .first()
        .and_then(|t| t[1].strip_prefix("twitter_id:"))
        .unwrap_or("");
    let empty = String::new();
    let handle_proof = handle_tags.first().and_then(|t| t.get(2)).unwrap_or(&empty);
    let id_proof = id_tags.first().and_then(|t| t.get(2)).unwrap_or(&empty);
    if !is_canonical_handle(handle) {
        errors.push(err(
            "twitter-handle",
            "twitter handle must be canonical lowercase",
        ));
    }
    if !is_digits(twitter_id) {
        errors.push(err(
            "twitter-id",
            "twitter_id must contain only decimal digits",
        ));
    }
    if handle_proof.is_empty() && id_proof.is_empty() {
        if handle_tags.first().map(|t| t.len()) != Some(2)
            || id_tags.first().map(|t| t.len()) != Some(2)
        {
            errors.push(err(
                "twitter-proof",
                "Proofless twitter tags must contain exactly two elements",
            ));
        }
    } else if !is_digits(handle_proof) || !is_digits(id_proof) {
        errors.push(err(
            "twitter-proof",
            "Twitter proof post IDs must contain only decimal digits",
        ));
    } else if handle_proof != id_proof {
        errors.push(err(
            "twitter-proof",
            "twitter and twitter_id tags must use the same proof post ID",
        ));
    } else if let (Some(h), Some(i)) = (handle_tags.first(), id_tags.first()) {
        if h.len() != i.len() {
            errors.push(err(
                "twitter-proof",
                "twitter and twitter_id tags must use matching proof hints",
            ));
        }
        if h.len() == 4 && !proof_hint_matches(h.get(3), handle_proof) {
            errors.push(err(
                "twitter-proof",
                "twitter i tag fourth value must match its proof post ID",
            ));
        }
        if i.len() == 4 && !proof_hint_matches(i.get(3), id_proof) {
            errors.push(err(
                "twitter-proof",
                "twitter_id i tag fourth value must match its proof post ID",
            ));
        }
    }
    if errors.is_empty() {
        Ok(Some(twitter_id.to_string()))
    } else {
        Err(errors)
    }
}

/// Validates a signed kind `10011`. The event is a valid replaceable winner
/// whenever its id and signature verify; the claim is present only when the
/// twitter tags are valid.
pub fn parse_claim(event: &Event, verify: bool) -> Result<ClaimRecord, Vec<ValidationError>> {
    if event.check_shape().is_err() {
        return Err(vec![ValidationError {
            code: "shape",
            message: "Event does not have a valid Nostr event shape".into(),
        }]);
    }
    if event.kind != KIND_IDENTITY {
        return Err(vec![ValidationError {
            code: "kind",
            message: "Event kind must be 10011".into(),
        }]);
    }
    if verify && let Err(e) = event.verify() {
        return Err(vec![ValidationError {
            code: e.code(),
            message: e.to_string(),
        }]);
    }
    Ok(ClaimRecord {
        id: event.id.clone(),
        pubkey: event.pubkey.clone(),
        created_at: event.created_at,
        twitter_id: twitter_claim(event).ok().flatten(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn t(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn claims() {
        let keys = Keys::from_seed("p");
        let ok = keys.sign_event(
            1,
            KIND_IDENTITY,
            vec![t(&["i", "twitter:nasa"]), t(&["i", "twitter_id:11348282"])],
            "",
        );
        assert_eq!(
            parse_claim(&ok, true).unwrap().twitter_id.as_deref(),
            Some("11348282")
        );

        let legacy = keys.sign_event(
            1,
            KIND_IDENTITY,
            vec![
                t(&["i", "twitter:nasa", "99"]),
                t(&["i", "twitter_id:11348282", "99"]),
            ],
            "",
        );
        assert_eq!(
            parse_claim(&legacy, true).unwrap().twitter_id.as_deref(),
            Some("11348282")
        );

        let structured = keys.sign_event(
            1,
            KIND_IDENTITY,
            vec![
                t(&["i", "twitter:nasa", "99", "post:id:99"]),
                t(&["i", "twitter_id:11348282", "99", "post:id:99"]),
            ],
            "",
        );
        assert!(parse_claim(&structured, true).unwrap().twitter_id.is_some());

        let upper = keys.sign_event(
            1,
            KIND_IDENTITY,
            vec![t(&["i", "twitter:NASA"]), t(&["i", "twitter_id:11348282"])],
            "",
        );
        assert_eq!(parse_claim(&upper, true).unwrap().twitter_id, None);

        let revoked = keys.sign_event(2, KIND_IDENTITY, vec![t(&["i", "github:x", "p"])], "");
        assert_eq!(parse_claim(&revoked, true).unwrap().twitter_id, None);

        let mismatched = keys.sign_event(
            1,
            KIND_IDENTITY,
            vec![
                t(&["i", "twitter:nasa", "1"]),
                t(&["i", "twitter_id:11348282", "2"]),
            ],
            "",
        );
        assert_eq!(parse_claim(&mismatched, true).unwrap().twitter_id, None);

        let mut forged = ok.clone();
        forged.pubkey = Keys::from_seed("q").pubkey().to_string();
        assert!(parse_claim(&forged, true).is_err());
    }
}
