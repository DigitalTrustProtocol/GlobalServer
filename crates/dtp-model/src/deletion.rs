//! NIP-09 kind `5` deletions that target the held kinds.

use crate::event::Event;
use crate::{KIND_DELETION, KIND_IDENTITY, KIND_RATING, KIND_TRUST, ValidationError, is_hex64};

/// One deletion target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionTarget {
    /// `e` tag: an event id.
    Event(String),
    /// `a` tag: an address `kind:pubkey:d` (only the author's own, held kinds).
    Address {
        kind: u32,
        pubkey: String,
        d: String,
    },
}

/// A validated kind `5`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deletion {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub targets: Vec<DeletionTarget>,
    /// Kinds named by `k` tags (may be empty).
    pub kinds: Vec<u32>,
}

impl Deletion {
    /// `true` when the deletion can concern a held kind: an address of a held
    /// kind, an explicit `k` of a held kind, or event ids with no `k` tag.
    pub fn may_target_held_kinds(&self) -> bool {
        let held = |k: u32| matches!(k, KIND_TRUST | KIND_RATING | KIND_IDENTITY);
        self.targets.iter().any(|t| match t {
            DeletionTarget::Address { kind, .. } => held(*kind),
            DeletionTarget::Event(_) => {
                self.kinds.is_empty() || self.kinds.iter().any(|k| held(*k))
            }
        })
    }
}

/// Parses and validates a kind `5`. Addresses by other authors are ignored
/// (NIP-09: only the author may delete).
pub fn parse_deletion(event: &Event, verify: bool) -> Result<Deletion, Vec<ValidationError>> {
    let err = |code, msg: &str| {
        vec![ValidationError {
            code,
            message: msg.to_string(),
        }]
    };
    if event.check_shape().is_err() {
        return Err(err(
            "shape",
            "Event does not have a valid Nostr event shape",
        ));
    }
    if event.kind != KIND_DELETION {
        return Err(err("kind", "Event kind must be 5"));
    }
    if verify && let Err(e) = event.verify() {
        return Err(err(e.code(), &e.to_string()));
    }
    let mut targets = Vec::new();
    for tag in &event.tags {
        match (tag.first().map(String::as_str), tag.get(1)) {
            (Some("e"), Some(id)) if is_hex64(id) => {
                targets.push(DeletionTarget::Event(id.clone()));
            }
            (Some("a"), Some(addr)) => {
                let mut parts = addr.splitn(3, ':');
                let kind = parts.next().and_then(|k| k.parse::<u32>().ok());
                let pubkey = parts.next().unwrap_or("");
                let d = parts.next();
                if let (Some(kind), Some(d)) = (kind, d)
                    && pubkey == event.pubkey
                {
                    targets.push(DeletionTarget::Address {
                        kind,
                        pubkey: pubkey.to_string(),
                        d: d.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    let kinds = event
        .tags_named("k")
        .filter_map(|t| t.get(1).and_then(|k| k.parse::<u32>().ok()))
        .collect();
    if targets.is_empty() {
        return Err(err("no-target", "Deletion names no event or address"));
    }
    Ok(Deletion {
        id: event.id.clone(),
        pubkey: event.pubkey.clone(),
        created_at: event.created_at,
        targets,
        kinds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    #[test]
    fn parses_targets() {
        let keys = Keys::from_seed("a");
        let other = Keys::from_seed("b");
        let id = "ab".repeat(32);
        let ev = keys.sign_event(
            10,
            KIND_DELETION,
            vec![
                vec!["e".into(), id.clone()],
                vec![
                    "a".into(),
                    format!("32009:{}:{}", keys.pubkey(), "cd".repeat(32)),
                ],
                vec![
                    "a".into(),
                    format!("32009:{}:{}", other.pubkey(), "cd".repeat(32)),
                ],
                vec!["k".into(), "32009".into()],
            ],
            "",
        );
        let d = parse_deletion(&ev, true).unwrap();
        assert_eq!(d.targets.len(), 2);
        assert_eq!(d.targets[0], DeletionTarget::Event(id));
        assert!(matches!(
            d.targets[1],
            DeletionTarget::Address { kind: 32009, .. }
        ));
        assert!(d.may_target_held_kinds());

        let unrelated = keys.sign_event(
            10,
            KIND_DELETION,
            vec![
                vec!["e".into(), "ab".repeat(32)],
                vec!["k".into(), "1".into()],
            ],
            "",
        );
        assert!(
            !parse_deletion(&unrelated, true)
                .unwrap()
                .may_target_held_kinds()
        );

        let empty = keys.sign_event(10, KIND_DELETION, vec![], "");
        assert!(parse_deletion(&empty, true).is_err());
    }
}
