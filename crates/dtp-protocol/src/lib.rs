//! `dtp-protocol`: wire types of resolver protocol v1 (TrustGraph
//! `resolver-api.md`): NIP-01 framing, NIP-42 authentication, the NIP-43
//! membership list, limited `REQ` filters, and `DTP` messages.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use dtp_model::{
    Event, KIND_AUTH, KIND_DELETION, KIND_IDENTITY, KIND_MEMBERSHIP, KIND_RATING, KIND_ROLE,
    KIND_TRUST, Keys,
};

/// Every operation of protocol v1 (NIP-11 `dtp.capabilities`).
pub const CAPABILITIES: &[&str] = &[
    "session.update",
    "info",
    "trust.query",
    "trust.batch",
    "rating.query",
    "rating.batch",
    "graph.field",
    "lookup.incoming",
    "lookup.outgoing",
    "lookup.counts",
    "lookup.batch",
    "graph.neighborhood",
    "graph.frontier",
    "identity.claims",
    "subscribe",
    "unsubscribe",
];

/// Push topics.
pub const TOPICS: &[&str] = &["graph", "coverage", "want"];

/// Kinds accepted by `EVENT`.
pub fn is_ingest_kind(kind: u32) -> bool {
    matches!(
        kind,
        KIND_TRUST | KIND_RATING | KIND_IDENTITY | KIND_DELETION
    )
}

/// A client → server message.
#[derive(Clone, Debug, PartialEq)]
pub enum ClientMsg {
    Event(Value),
    Auth(Value),
    Req {
        sub: String,
        filters: Vec<Value>,
    },
    Close(String),
    Dtp {
        req_id: Value,
        op: String,
        params: Value,
    },
    DtpCancel(Value),
}

/// Parses one NIP-01 frame. `Err` carries a `NOTICE` text.
pub fn parse_client(text: &str) -> Result<ClientMsg, String> {
    let value: Value =
        serde_json::from_str(text).map_err(|_| "invalid: message is not JSON".to_string())?;
    let Value::Array(items) = value else {
        return Err("invalid: message must be a JSON array".into());
    };
    let name = items.first().and_then(Value::as_str).unwrap_or("");
    match name {
        "EVENT" if items.len() == 2 => Ok(ClientMsg::Event(items[1].clone())),
        "AUTH" if items.len() == 2 => Ok(ClientMsg::Auth(items[1].clone())),
        "REQ" if items.len() >= 2 => {
            let sub = items[1]
                .as_str()
                .ok_or("invalid: REQ subscription id must be a string")?;
            Ok(ClientMsg::Req {
                sub: sub.to_string(),
                filters: items[2..].to_vec(),
            })
        }
        "CLOSE" if items.len() == 2 => Ok(ClientMsg::Close(
            items[1].as_str().unwrap_or("").to_string(),
        )),
        "DTP" if items.len() == 3 || items.len() == 4 => {
            let req_id = items[1].clone();
            if !(req_id.is_string() || req_id.is_number()) {
                return Err("invalid: DTP request id must be a string or number".into());
            }
            let op = items[2]
                .as_str()
                .ok_or("invalid: DTP op must be a string")?
                .to_string();
            let params = items
                .get(3)
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            Ok(ClientMsg::Dtp { req_id, op, params })
        }
        "DTP-CANCEL" if items.len() == 2 => Ok(ClientMsg::DtpCancel(items[1].clone())),
        _ => Err(format!("invalid: unsupported message {name}")),
    }
}

pub fn ok(event_id: &str, accepted: bool, message: &str) -> String {
    json!(["OK", event_id, accepted, message]).to_string()
}

pub fn notice(message: &str) -> String {
    json!(["NOTICE", message]).to_string()
}

pub fn auth_challenge(challenge: &str) -> String {
    json!(["AUTH", challenge]).to_string()
}

pub fn event(sub: &str, event: &Event) -> String {
    json!(["EVENT", sub, event]).to_string()
}

pub fn eose(sub: &str) -> String {
    json!(["EOSE", sub]).to_string()
}

pub fn closed(sub: &str, message: &str) -> String {
    json!(["CLOSED", sub, message]).to_string()
}

pub fn dtp_ok(req_id: &Value, result: &Value) -> String {
    json!(["DTP-OK", req_id, result]).to_string()
}

pub fn dtp_err(req_id: &Value, code: &str, message: &str) -> String {
    json!(["DTP-ERR", req_id, code, message]).to_string()
}

pub fn dtp_push(topic: &str, data: &Value) -> String {
    json!(["DTP-PUSH", topic, data]).to_string()
}

/// Normalizes a relay URL for the NIP-42 `relay` tag comparison: lowercase
/// scheme and host, no trailing slash.
pub fn normalize_relay_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
            let path = if path.is_empty() {
                String::new()
            } else {
                format!("/{path}")
            };
            format!(
                "{}://{}{}",
                scheme.to_ascii_lowercase(),
                host.to_ascii_lowercase(),
                path
            )
        }
        None => trimmed.to_ascii_lowercase(),
    }
}

/// Verifies a NIP-42 kind 22242 event. Returns the authenticated pubkey or
/// the `OK` message (with prefix) explaining the failure.
pub fn verify_auth(
    event: &Value,
    challenge: &str,
    relay_urls: &[String],
    now: u64,
) -> Result<(String, String), (String, String)> {
    let id = event
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let event = Event::from_value(event)
        .map_err(|_| (id.clone(), "invalid: malformed auth event".to_string()))?;
    if event.kind != KIND_AUTH {
        return Err((event.id, "invalid: auth event must be kind 22242".into()));
    }
    if event.created_at + 600 < now || event.created_at > now + 600 {
        return Err((
            event.id,
            "invalid: auth event created_at is not within 10 minutes".into(),
        ));
    }
    let tag = |name: &str| {
        event
            .tags_named(name)
            .next()
            .and_then(|t| t.get(1))
            .cloned()
    };
    if tag("challenge").as_deref() != Some(challenge) {
        return Err((event.id, "invalid: challenge does not match".into()));
    }
    let relay = tag("relay").map(|r| normalize_relay_url(&r));
    if !relay_urls.is_empty()
        && !relay
            .as_ref()
            .is_some_and(|r| relay_urls.iter().any(|u| normalize_relay_url(u) == *r))
    {
        return Err((
            event.id,
            "invalid: relay tag does not name this server".into(),
        ));
    }
    if event.verify().is_err() {
        return Err((event.id, "invalid: bad auth event id or signature".into()));
    }
    Ok((event.id, event.pubkey))
}

/// Membership roles (NIP-43 kind 33534 `d` values).
pub const ROLES: &[&str] = &["read", "write", "admin"];

/// The NIP-43 whitelist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    pub members: BTreeMap<String, BTreeSet<String>>,
}

impl Membership {
    pub fn has_role(&self, pubkey: &str, role: &str) -> bool {
        self.members
            .get(pubkey)
            .is_some_and(|roles| roles.contains(role) || roles.contains("admin"))
    }

    pub fn add(&mut self, pubkey: &str, role: &str) -> bool {
        if !dtp_model::is_hex64(pubkey) || !ROLES.contains(&role) {
            return false;
        }
        self.members
            .entry(pubkey.to_string())
            .or_default()
            .insert(role.to_string())
    }

    pub fn remove(&mut self, pubkey: &str, role: Option<&str>) -> bool {
        match role {
            None => self.members.remove(pubkey).is_some(),
            Some(r) => {
                let Some(roles) = self.members.get_mut(pubkey) else {
                    return false;
                };
                let removed = roles.remove(r);
                if roles.is_empty() {
                    self.members.remove(pubkey);
                }
                removed
            }
        }
    }

    pub fn to_json(&self) -> Value {
        Value::Array(
            self.members
                .iter()
                .map(|(pk, roles)| json!({ "pubkey": pk, "roles": roles.iter().collect::<Vec<_>>() }))
                .collect(),
        )
    }

    pub fn from_json(value: &Value) -> Membership {
        let mut m = Membership::default();
        for item in value.as_array().into_iter().flatten() {
            let Some(pk) = item.get("pubkey").and_then(Value::as_str) else {
                continue;
            };
            for role in item
                .get("roles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(r) = role.as_str() {
                    m.add(pk, r);
                }
            }
        }
        m
    }

    pub fn counts(&self) -> Value {
        let count = |r: &str| {
            self.members
                .values()
                .filter(|roles| roles.contains(r))
                .count()
        };
        json!({ "read": count("read"), "write": count("write"), "admin": count("admin") })
    }

    /// Signs the kind 13534 list and the 33534 role definitions with the
    /// server key.
    pub fn sign(&self, keys: &Keys, now: u64) -> Vec<Event> {
        let mut tags: Vec<Vec<String>> = vec![vec!["-".into()]];
        for (pk, roles) in &self.members {
            let mut tag = vec!["member".to_string(), pk.clone()];
            tag.extend(roles.iter().cloned());
            tags.push(tag);
        }
        let mut events = vec![keys.sign_event(now, KIND_MEMBERSHIP, tags, "")];
        let descriptions = [
            (
                "read",
                "May run resolver and lookup operations and REQ reads",
            ),
            ("write", "May push EVENTs (kinds 32009, 32014, 10011, 5)"),
            ("admin", "May manage members (NIP-86)"),
        ];
        for (role, description) in descriptions {
            events.push(keys.sign_event(
                now,
                KIND_ROLE,
                vec![vec!["d".into(), role.into()], vec!["-".into()]],
                description,
            ));
        }
        events
    }
}

/// A validated limited read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReqFilter {
    Ids(Vec<String>),
    Authors {
        authors: Vec<String>,
        kinds: Vec<u32>,
        limit: usize,
    },
    Membership {
        kinds: Vec<u32>,
    },
}

/// Checks a `REQ` filter against the v1 read rules; `Err` is the `CLOSED`
/// message.
pub fn parse_filter(filter: &Value) -> Result<ReqFilter, String> {
    let Some(obj) = filter.as_object() else {
        return Err("invalid: filter must be an object".into());
    };
    let strings = |key: &str| -> Option<Result<Vec<String>, String>> {
        obj.get(key).map(|v| {
            v.as_array()
                .ok_or(format!("invalid: {key} must be an array"))?
                .iter()
                .map(|s| {
                    s.as_str()
                        .filter(|s| dtp_model::is_hex64(s))
                        .map(str::to_string)
                        .ok_or(format!("invalid: {key} must hold 64-hex strings"))
                })
                .collect()
        })
    };
    let kinds: Option<Vec<u32>> = obj.get("kinds").map(|v| {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|k| k.as_u64().map(|k| k as u32))
            .collect()
    });
    let limit = obj
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(500)
        .min(500) as usize;
    let allowed = obj.keys().all(|k| {
        matches!(
            k.as_str(),
            "ids" | "authors" | "kinds" | "limit" | "since" | "until"
        )
    });
    if !allowed {
        return Err("unsupported: only ids, authors + kinds, and NIP-43 kinds are served".into());
    }
    if let Some(ids) = strings("ids") {
        let ids = ids?;
        if ids.len() > 500 {
            return Err("unsupported: at most 500 ids per filter".into());
        }
        return Ok(ReqFilter::Ids(ids));
    }
    if let Some(kinds) = &kinds
        && !kinds.is_empty()
        && kinds
            .iter()
            .all(|k| matches!(*k, KIND_MEMBERSHIP | KIND_ROLE))
        && obj.get("authors").is_none()
    {
        return Ok(ReqFilter::Membership {
            kinds: kinds.clone(),
        });
    }
    if let Some(authors) = strings("authors") {
        let authors = authors?;
        let kinds = kinds.unwrap_or_default();
        if authors.is_empty() || authors.len() > 20 {
            return Err("unsupported: authors filters need 1–20 authors".into());
        }
        if kinds.is_empty()
            || !kinds
                .iter()
                .all(|k| matches!(*k, KIND_TRUST | KIND_RATING | KIND_IDENTITY))
        {
            return Err("unsupported: authors filters need kinds from 32009, 32014, 10011".into());
        }
        return Ok(ReqFilter::Authors {
            authors,
            kinds,
            limit,
        });
    }
    Err("unsupported: only ids, authors + kinds, and NIP-43 kinds are served".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frames() {
        assert!(matches!(
            parse_client(r#"["EVENT",{}]"#),
            Ok(ClientMsg::Event(_))
        ));
        assert!(matches!(
            parse_client(r#"["DTP","1","info"]"#),
            Ok(ClientMsg::Dtp { .. })
        ));
        assert!(matches!(
            parse_client(r#"["DTP",7,"info",{}]"#),
            Ok(ClientMsg::Dtp { .. })
        ));
        assert!(matches!(
            parse_client(r#"["REQ","s",{"ids":[]}]"#),
            Ok(ClientMsg::Req { .. })
        ));
        assert!(parse_client(r#"["NOPE"]"#).is_err());
        assert!(parse_client("{").is_err());
        assert!(parse_client(r#"["DTP",{},"info"]"#).is_err());
    }

    #[test]
    fn auth_checks() {
        let keys = Keys::from_seed("writer");
        let url = "ws://127.0.0.1:3880/".to_string();
        let ev = keys.sign_event(
            1_000,
            KIND_AUTH,
            vec![
                vec!["relay".into(), "WS://127.0.0.1:3880".into()],
                vec!["challenge".into(), "abc".into()],
            ],
            "",
        );
        let v = ev.to_value();
        assert_eq!(
            verify_auth(&v, "abc", std::slice::from_ref(&url), 1_100).map(|r| r.1),
            Ok(keys.pubkey().to_string())
        );
        assert!(verify_auth(&v, "other", std::slice::from_ref(&url), 1_100).is_err());
        assert!(verify_auth(&v, "abc", std::slice::from_ref(&url), 2_000).is_err());
        assert!(verify_auth(&v, "abc", &["ws://elsewhere/".to_string()], 1_100).is_err());
    }

    #[test]
    fn filters() {
        let pk = "ab".repeat(32);
        assert!(matches!(
            parse_filter(&json!({ "ids": [pk] })),
            Ok(ReqFilter::Ids(_))
        ));
        assert!(matches!(
            parse_filter(&json!({ "authors": [pk], "kinds": [32009] })),
            Ok(ReqFilter::Authors { .. })
        ));
        assert!(matches!(
            parse_filter(&json!({ "kinds": [13534] })),
            Ok(ReqFilter::Membership { .. })
        ));
        assert!(parse_filter(&json!({ "kinds": [1] })).is_err());
        assert!(parse_filter(&json!({ "authors": [pk], "kinds": [1] })).is_err());
        assert!(parse_filter(&json!({ "#p": [pk] })).is_err());
    }

    #[test]
    fn membership_signing() {
        let mut m = Membership::default();
        let pk = "ab".repeat(32);
        assert!(m.add(&pk, "write"));
        assert!(!m.add("zz", "write"));
        assert!(m.has_role(&pk, "write"));
        assert!(!m.has_role(&pk, "read"));
        let keys = Keys::from_seed("server");
        let events = m.sign(&keys, 5);
        assert_eq!(events[0].kind, KIND_MEMBERSHIP);
        assert!(
            events[0]
                .tags
                .iter()
                .any(|t| t[0] == "member" && t[1] == pk && t[2] == "write")
        );
        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|e| e.verify().is_ok()));
        assert_eq!(Membership::from_json(&m.to_json()), m);
    }
}
