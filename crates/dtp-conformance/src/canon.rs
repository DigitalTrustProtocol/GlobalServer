//! Placeholders and canonical comparison (conformance.md § Canonical
//! comparison).

use serde_json::{Map, Value, json};

/// Expands `@name` tokens to `sha256("name")` in every string except
/// `content` fields.
pub fn expand_placeholders(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(expand_str(s)),
        Value::Array(items) => Value::Array(items.iter().map(expand_placeholders).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if k == "content" {
                        v.clone()
                    } else {
                        expand_placeholders(v)
                    };
                    (expand_str(k), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

pub fn expand_str(s: &str) -> String {
    if !s.contains('@') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' && i + 1 < chars.len() && is_name_char(chars[i + 1]) {
            let mut j = i + 1;
            while j < chars.len() && is_name_char(chars[j]) {
                j += 1;
            }
            // A trailing '.' belongs to the surrounding text.
            while j > i + 1 && chars[j - 1] == '.' {
                j -= 1;
            }
            let name: String = chars[i + 1..j].iter().collect();
            out.push_str(&dtp_model::sha256_hex(&name));
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn wire_of(node: &Value) -> Option<String> {
    let s = node.get("subject")?;
    Some(format!(
        "{}:{}",
        s.get("type")?.as_str()?,
        s.get("value")?.as_str()?
    ))
}

/// Canonical view of a `{ nodes, edges }` graph shape: nodes keyed by wire
/// subject, edges by event id, numeric ids replaced by subjects.
pub fn canon_view(view: &Value) -> Value {
    let Some(nodes) = view.get("nodes").and_then(Value::as_array) else {
        return view.clone();
    };
    let mut by_id: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut out_nodes = Map::new();
    for n in nodes {
        let Some(wire) = wire_of(n) else { continue };
        if let Some(id) = n.get("id") {
            by_id.insert(id.to_string(), wire.clone());
        }
        let mut m = Map::new();
        for (k, v) in n.as_object().into_iter().flatten() {
            if !matches!(k.as_str(), "id" | "label" | "subject") {
                m.insert(k.clone(), v.clone());
            }
        }
        out_nodes.insert(wire, Value::Object(m));
    }
    let map_ref = |v: &Value| -> Value {
        match v {
            Value::String(s) if s.contains(':') => v.clone(),
            other => by_id
                .get(&other.to_string())
                .map_or(other.clone(), |w| json!(w)),
        }
    };
    let mut out_edges = Map::new();
    for e in view
        .get("edges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let key = e
            .get("eventId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| e.get("id").map(|v| v.to_string()).unwrap_or_default());
        let mut m = Map::new();
        for (k, v) in e.as_object().into_iter().flatten() {
            match k.as_str() {
                "id" => {}
                "from" | "to" => {
                    m.insert(k.clone(), map_ref(v));
                }
                _ => {
                    m.insert(k.clone(), v.clone());
                }
            }
        }
        out_edges.insert(key, Value::Object(m));
    }
    json!({ "nodes": out_nodes, "edges": out_edges })
}

fn sort_evidence(items: &mut [Value]) {
    items.sort_by(|a, b| {
        let d = |v: &Value| v.get("distance").and_then(Value::as_u64).unwrap_or(0);
        let c = |v: &Value| v.get("createdAt").and_then(Value::as_u64).unwrap_or(0);
        let id = |v: &Value| {
            v.get("eventId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        d(a).cmp(&d(b))
            .then(c(b).cmp(&c(a)))
            .then(id(a).cmp(&id(b)))
    });
}

/// Canonicalizes a result (either side) before comparison.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                match k.as_str() {
                    "computedAt" | "graphVersion" | "instanceId" => {}
                    "statements" | "claims" => {
                        let mut items: Vec<Value> = v.as_array().cloned().unwrap_or_default();
                        if items.iter().all(Value::is_object) {
                            sort_evidence(&mut items);
                        }
                        out.insert(
                            k.clone(),
                            Value::Array(items.iter().map(canonicalize).collect()),
                        );
                    }
                    "sourceEventIds" => {
                        let mut ids: Vec<Value> = v.as_array().cloned().unwrap_or_default();
                        ids.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                        out.insert(k.clone(), Value::Array(ids));
                    }
                    "pathView" => {
                        out.insert(k.clone(), canon_view(v));
                    }
                    "ratingEdges" => {
                        // Numeric ids are instance-local: map them through
                        // the sibling pathView's nodes, key edges by event id.
                        let mut view = map
                            .get("pathView")
                            .cloned()
                            .unwrap_or(json!({ "nodes": [] }));
                        view["edges"] = v.clone();
                        out.insert(k.clone(), canon_view(&view)["edges"].clone());
                    }
                    _ => {
                        out.insert(k.clone(), canonicalize(v));
                    }
                }
            }
            if map.contains_key("nodes")
                && map.contains_key("edges")
                && map.contains_key("centerId")
            {
                let view = canon_view(value);
                out.insert("nodes".into(), view["nodes"].clone());
                out.insert("edges".into(), view["edges"].clone());
                out.remove("centerId");
            }
            sort_keys(Value::Object(out))
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Orders object keys recursively so canonical JSON strings compare equal
/// regardless of insertion order.
pub fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, sort_keys(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

fn is_wildcard(v: &Value) -> bool {
    matches!(v, Value::String(s) if s == "…" || s == "*" || s == "...")
}

/// Subset comparison: every field of `expected` must match `actual`.
/// Numbers compare with tolerance `1e-9`; `"…"` matches anything.
pub fn compare(expected: &Value, actual: Option<&Value>, path: &str, errors: &mut Vec<String>) {
    if is_wildcard(expected) {
        return;
    }
    let Some(actual) = actual else {
        let absent_ok = matches!(expected, Value::Null)
            || (path.ends_with(".neutral") && expected.as_u64() == Some(0))
            || (path.ends_with(".truncated") && expected.as_bool() == Some(false))
            || (path.ends_with(".statementsTruncated") && expected.as_bool() == Some(false));
        if !absent_ok {
            errors.push(format!("{path}: missing (expected {expected})"));
        }
        return;
    };
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, ev) in e {
                if matches!(
                    k.as_str(),
                    "computedAt" | "graphVersion" | "label" | "instanceId"
                ) {
                    continue;
                }
                compare(ev, a.get(k), &format!("{path}.{k}"), errors);
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                errors.push(format!(
                    "{path}: length {} != expected {}",
                    a.len(),
                    e.len()
                ));
                return;
            }
            for (i, (ev, av)) in e.iter().zip(a).enumerate() {
                compare(ev, Some(av), &format!("{path}[{i}]"), errors);
            }
        }
        (Value::Number(e), Value::Number(a)) => {
            let (e, a) = (
                e.as_f64().unwrap_or(f64::NAN),
                a.as_f64().unwrap_or(f64::NAN),
            );
            if (e - a).abs() > 1e-9 {
                errors.push(format!("{path}: {a} != expected {e}"));
            }
        }
        (e, a) => {
            if e != a {
                errors.push(format!("{path}: {a} != expected {e}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders() {
        let h = dtp_model::sha256_hex("alice");
        assert_eq!(expand_str("@alice"), h);
        assert_eq!(expand_str("32009:@alice:…"), format!("32009:{h}:…"));
        assert_eq!(expand_str("p:@alice"), format!("p:{h}"));
        let v = expand_placeholders(&json!({ "content": "hi @alice", "pubkey": "@alice" }));
        assert_eq!(v["content"], "hi @alice");
        assert_eq!(v["pubkey"], h);
    }

    #[test]
    fn subset_compare() {
        let mut errs = Vec::new();
        compare(
            &json!({ "a": 1, "b": ["…"] }),
            Some(&json!({ "a": 1.0, "b": [3], "c": 9 })),
            "$",
            &mut errs,
        );
        assert!(errs.is_empty(), "{errs:?}");
        compare(&json!({ "a": 2 }), Some(&json!({ "a": 1 })), "$", &mut errs);
        assert_eq!(errs.len(), 1);
    }
}
