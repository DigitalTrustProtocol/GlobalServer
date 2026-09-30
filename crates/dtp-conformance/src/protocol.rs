//! Protocol cases: one signed event + scope profile → verdict, eligibility,
//! and the normalized record.

use serde_json::{Map, Value, json};

use dtp_model::statement::parse_statement;
use dtp_model::{
    EdgeRecord, Event, KIND_DELETION, KIND_IDENTITY, KIND_RATING, KIND_TRUST, RecordValue,
    ScopeProfile,
};

use crate::canon::compare;
use crate::case::CaseOutcome;

/// A normalized record in the corpus field names (wot-model §2.1).
pub fn record_json(r: &EdgeRecord) -> Value {
    let mut m = Map::new();
    m.insert("addressKey".into(), json!(r.address_key()));
    m.insert("id".into(), json!(r.id));
    m.insert("pubkey".into(), json!(r.pubkey));
    m.insert("kind".into(), json!(r.kind));
    m.insert("created_at".into(), json!(r.created_at));
    m.insert("subjectType".into(), json!(r.subject_type.as_str()));
    m.insert("subject".into(), json!(r.subject));
    m.insert("context".into(), json!(r.context));
    match r.value {
        Some(RecordValue::Trust(v)) => {
            m.insert("value".into(), json!(v));
        }
        Some(RecordValue::Score(s)) => {
            m.insert("value".into(), s.to_json());
        }
        None => {}
    }
    if let Some(x) = r.activate {
        m.insert("activate".into(), json!(x));
    }
    if let Some(y) = r.expire {
        m.insert("expire".into(), json!(y));
    }
    m.insert("scopeRank".into(), json!(r.scope_rank));
    if let Some(h) = &r.hint_pubkey {
        m.insert("hintPubkey".into(), json!(h));
    }
    m.insert("content".into(), json!(r.content));
    m.insert("labels".into(), json!(r.labels));
    if !r.label_hints.is_empty() {
        let hints: Map<String, Value> = r
            .label_hints
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        m.insert("labelHints".into(), Value::Object(hints));
    }
    m.insert("dTag".into(), json!(r.d));
    Value::Object(m)
}

/// Validates one event and returns the verdict object compared by cases.
pub fn verdict(event_value: &Value, profile: ScopeProfile) -> Value {
    let event = match Event::from_value(event_value) {
        Ok(e) => e,
        Err(e) => return json!({ "valid": false, "errors": [e.code()] }),
    };
    match event.kind {
        KIND_TRUST | KIND_RATING => match parse_statement(&event, true) {
            Err(errors) => {
                json!({ "valid": false, "errors": errors.iter().map(|e| e.code).collect::<Vec<_>>() })
            }
            Ok(parsed) => match parsed.normalize(profile) {
                Ok(record) => {
                    json!({ "valid": true, "errors": [], "eligible": true, "record": record_json(&record) })
                }
                Err(_) => json!({ "valid": true, "errors": [], "eligible": false }),
            },
        },
        KIND_IDENTITY => match dtp_model::parse_claim(&event, true) {
            Err(errors) => {
                json!({ "valid": false, "errors": errors.iter().map(|e| e.code).collect::<Vec<_>>() })
            }
            Ok(claim) => json!({
                "valid": true, "errors": [], "eligible": true,
                "claim": claim.twitter_id.map(|x| json!({ "pubkey": claim.pubkey, "twitterId": x })),
            }),
        },
        KIND_DELETION => match dtp_model::parse_deletion(&event, true) {
            Err(errors) => {
                json!({ "valid": false, "errors": errors.iter().map(|e| e.code).collect::<Vec<_>>() })
            }
            Ok(d) => json!({ "valid": true, "errors": [], "eligible": d.may_target_held_kinds() }),
        },
        _ => json!({ "valid": false, "errors": ["kind"] }),
    }
}

pub fn run_protocol_case(case: &Value) -> CaseOutcome {
    let Some(event) = case.get("event") else {
        return CaseOutcome::Skip("protocol case without event".into());
    };
    let profile = case
        .get("profile")
        .and_then(Value::as_str)
        .and_then(ScopeProfile::parse)
        .unwrap_or_default();
    let Some(expect) = case.get("expect") else {
        return CaseOutcome::Skip("protocol case without expect".into());
    };
    let actual = verdict(event, profile);
    let mut errors = Vec::new();
    for key in ["valid", "eligible", "record", "claim"] {
        if let Some(e) = expect.get(key) {
            compare(e, actual.get(key), &format!("$.{key}"), &mut errors);
        }
    }
    if let Some(Value::Array(codes)) = expect.get("errors") {
        let got: Vec<&str> = actual["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for c in codes.iter().filter_map(Value::as_str) {
            if !got.contains(&c) {
                errors.push(format!("$.errors: missing code {c} (got {got:?})"));
            }
        }
        if codes.is_empty() && !got.is_empty() {
            errors.push(format!("$.errors: expected none, got {got:?}"));
        }
    }
    if errors.is_empty() {
        CaseOutcome::Pass
    } else {
        CaseOutcome::Fail(errors)
    }
}
