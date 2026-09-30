//! Resolver query parameters (resolver-api § Query fields) and limits.

use serde_json::{Map, Value};

use dtp_model::grammar::is_canonical_context;
use dtp_model::score::{clamp_green, clamp_red};
use dtp_model::{Subject, SubjectType};

use crate::walk::BindingMode;

/// Shared guardrail values (`dtp.limits`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub operation_deadline_ms: u64,
    pub batch_deadline_ms: u64,
    pub max_depth: u8,
    pub max_reached_nodes: usize,
    pub max_walk_records: usize,
    pub max_statement_limit: usize,
    pub max_path_nodes: usize,
    pub max_neighborhood_limit: usize,
    pub max_batch_items: usize,
    pub max_lookup_keys: usize,
    pub max_lookup_page: usize,
    pub max_lookup_batch: usize,
    pub max_lookup_records: usize,
    pub max_in_flight: usize,
    pub max_pending_oks: usize,
    pub max_writer_connections: usize,
    pub max_connections: usize,
    pub max_unsent_output: usize,
    pub max_message_length: usize,
}

impl Limits {
    /// Protocol defaults (resolver-api § Guardrails).
    pub fn protocol_defaults() -> Limits {
        Limits {
            operation_deadline_ms: 500,
            batch_deadline_ms: 1_000,
            max_depth: 7,
            max_reached_nodes: 5_000_000,
            max_walk_records: 50_000_000,
            max_statement_limit: 500,
            max_path_nodes: 1_000,
            max_neighborhood_limit: 500,
            max_batch_items: 200,
            max_lookup_keys: 50,
            max_lookup_page: 500,
            max_lookup_batch: 50,
            max_lookup_records: 5_000_000,
            max_in_flight: 32,
            max_pending_oks: 5_000,
            max_writer_connections: 8,
            max_connections: 16,
            max_unsent_output: 8 * 1024 * 1024,
            max_message_length: 4 * 1024 * 1024,
        }
    }

    /// Global deployment values (api-privacy-operations.md).
    pub fn global_defaults() -> Limits {
        Limits {
            operation_deadline_ms: 250,
            batch_deadline_ms: 500,
            max_depth: 6,
            max_in_flight: 16,
            ..Limits::protocol_defaults()
        }
    }

    /// The NIP-11 `dtp.limits` object.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "operationDeadline": self.operation_deadline_ms,
            "batchDeadline": self.batch_deadline_ms,
            "maxDepth": self.max_depth,
            "maxReachedNodes": self.max_reached_nodes,
            "maxWalkRecords": self.max_walk_records,
            "maxStatementLimit": self.max_statement_limit,
            "maxPathNodes": self.max_path_nodes,
            "maxNeighborhoodLimit": self.max_neighborhood_limit,
            "maxBatchItems": self.max_batch_items,
            "maxLookupKeys": self.max_lookup_keys,
            "maxLookupPage": self.max_lookup_page,
            "maxLookupBatch": self.max_lookup_batch,
            "maxLookupRecords": self.max_lookup_records,
            "maxInFlight": self.max_in_flight,
            "maxConnections": self.max_connections,
            "maxUnsentOutput": self.max_unsent_output,
            "maxPendingOks": self.max_pending_oks,
            "maxWriterConnections": self.max_writer_connections,
        })
    }
}

/// A parameter error (`DTP-ERR invalid`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamError(pub String);

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn invalid<T>(msg: impl Into<String>) -> Result<T, ParamError> {
    Err(ParamError(msg.into()))
}

/// Merges session defaults under request params (`bounds` merged one level).
pub fn merge_defaults(
    defaults: &Map<String, Value>,
    params: &Map<String, Value>,
) -> Map<String, Value> {
    let mut merged = defaults.clone();
    for (key, value) in params {
        if key == "bounds"
            && let (Some(Value::Object(base)), Value::Object(over)) =
                (merged.get(key).cloned(), value)
        {
            let mut b = base;
            for (k, v) in over {
                b.insert(k.clone(), v.clone());
            }
            merged.insert(key.clone(), Value::Object(b));
            continue;
        }
        merged.insert(key.clone(), value.clone());
    }
    merged
}

/// Parses a wire subject `{ type, value }`.
pub fn parse_subject(value: Option<&Value>) -> Result<Subject, ParamError> {
    let Some(Value::Object(obj)) = value else {
        return invalid("subject must be an object { type, value }");
    };
    let ty = obj
        .get("type")
        .and_then(Value::as_str)
        .and_then(SubjectType::parse);
    let val = obj
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    match (ty, val) {
        (Some(ty), Some(val)) => Ok(Subject::new(ty, val)),
        _ => invalid("subject.type must be p, e, or i and subject.value non-empty"),
    }
}

pub fn parse_pubkey(value: &Value, name: &str) -> Result<String, ParamError> {
    let Some(s) = value.as_str() else {
        return invalid(format!("{name} must be a 64-hex pubkey"));
    };
    let lower = s.trim().to_ascii_lowercase();
    if !dtp_model::is_hex64(&lower) {
        return invalid(format!("{name} must be a 64-hex pubkey"));
    }
    Ok(lower)
}

pub fn opt_u64(params: &Map<String, Value>, key: &str) -> Result<Option<u64>, ParamError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_u64() {
            Some(n) => Ok(Some(n)),
            None => invalid(format!("{key} must be a non-negative integer")),
        },
    }
}

pub fn opt_str<'a>(
    params: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, ParamError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => invalid(format!("{key} must be a string")),
    }
}

pub fn opt_bool(params: &Map<String, Value>, key: &str) -> Result<bool, ParamError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => invalid(format!("{key} must be a boolean")),
    }
}

pub fn parse_context(
    params: &Map<String, Value>,
    key: &str,
    default: &str,
) -> Result<String, ParamError> {
    let context = opt_str(params, key)?.unwrap_or(default).to_string();
    if !is_canonical_context(&context) {
        return invalid(format!("{key} is not canonical"));
    }
    Ok(context)
}

/// A parsed resolver query (`trust.query` / `rating.query` item).
#[derive(Clone, Debug, PartialEq)]
pub struct ResolveQuery {
    pub root: String,
    pub subject: Subject,
    pub context: String,
    pub now: u64,
    pub max_depth: u8,
    pub format_path: bool,
    pub green: u64,
    pub red: u64,
    pub hop_context: String,
    pub statement_limit: usize,
    pub mode: BindingMode,
    pub deadline_ms: u64,
    pub labels: Vec<String>,
}

impl ResolveQuery {
    /// Parses query fields (already merged with session defaults).
    pub fn parse(
        params: &Map<String, Value>,
        limits: &Limits,
        server_now: u64,
    ) -> Result<ResolveQuery, ParamError> {
        let root = match params.get("rootPubkey") {
            None | Some(Value::Null) => {
                return invalid("rootPubkey is required (set it in session defaults or the query)");
            }
            Some(v) => parse_pubkey(v, "rootPubkey")?,
        };
        let subject = parse_subject(params.get("subject"))?;
        let context = parse_context(params, "context", "")?;
        let hop_context = parse_context(params, "hopContext", "identity")?;
        let now = opt_u64(params, "now")?.unwrap_or(server_now);
        let max_depth = match params.get("bounds").and_then(|b| b.get("maxDepth")) {
            None | Some(Value::Null) => 4,
            Some(v) => match v.as_u64() {
                Some(n) => n.min(7) as u8,
                None => return invalid("bounds.maxDepth must be a non-negative integer"),
            },
        }
        .min(limits.max_depth);
        let format_path = match opt_str(params, "format")? {
            None | Some("default") => false,
            Some("path") => true,
            Some(_) => return invalid("format must be default or path"),
        };
        let green = clamp_green(params.get("followTrustThreshold").and_then(Value::as_f64));
        let red = clamp_red(params.get("followTrustRed").and_then(Value::as_f64), green);
        let statement_limit = opt_u64(params, "statementLimit")?
            .unwrap_or(50)
            .min(limits.max_statement_limit as u64) as usize;
        let mode = match opt_str(params, "bindingMode")? {
            None => BindingMode::Lenient,
            Some(m) => BindingMode::parse(m)
                .ok_or_else(|| ParamError("bindingMode must be lenient or strict".into()))?,
        };
        let deadline_ms = opt_u64(params, "deadlineMs")?
            .unwrap_or(limits.operation_deadline_ms)
            .min(limits.operation_deadline_ms);
        let labels = match params.get("labels") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| ParamError("labels must be strings".into()))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|l| !l.is_empty())
                .collect(),
            Some(_) => return invalid("labels must be an array of strings"),
        };
        Ok(ResolveQuery {
            root,
            subject,
            context,
            now,
            max_depth,
            format_path,
            green,
            red,
            hop_context,
            statement_limit,
            mode,
            deadline_ms,
            labels,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn defaults_merge_and_parse() {
        let defaults = obj(json!({
            "rootPubkey": "AB".repeat(32), "bindingMode": "strict",
            "followTrustThreshold": 80, "bounds": { "maxDepth": 3 }, "statementLimit": 10
        }));
        let params = obj(json!({ "subject": { "type": "i", "value": "user:id:1" }, "bounds": {} }));
        let merged = merge_defaults(&defaults, &params);
        let q = ResolveQuery::parse(&merged, &Limits::global_defaults(), 99).unwrap();
        assert_eq!(q.root, "ab".repeat(32));
        assert_eq!(q.mode, BindingMode::Strict);
        assert_eq!(q.green, 80);
        assert_eq!(q.red, 25);
        assert_eq!(q.max_depth, 3);
        assert_eq!(q.statement_limit, 10);
        assert_eq!(q.now, 99);
        assert_eq!(q.hop_context, "identity");
        assert_eq!(q.deadline_ms, 250);
    }

    #[test]
    fn rejects_bad_params() {
        let limits = Limits::protocol_defaults();
        let bad = |v: Value| ResolveQuery::parse(&obj(v), &limits, 0).is_err();
        assert!(bad(json!({ "subject": { "type": "p", "value": "x" } })));
        assert!(bad(
            json!({ "rootPubkey": "zz", "subject": { "type": "p", "value": "x" } })
        ));
        let root = "ab".repeat(32);
        assert!(bad(
            json!({ "rootPubkey": root, "subject": { "type": "q", "value": "x" } })
        ));
        assert!(bad(
            json!({ "rootPubkey": root, "subject": { "type": "p", "value": "x" }, "context": "Bad" })
        ));
        assert!(bad(
            json!({ "rootPubkey": root, "subject": { "type": "p", "value": "x" }, "bindingMode": "x" })
        ));
        assert!(!bad(
            json!({ "rootPubkey": root, "subject": { "type": "p", "value": "x" }, "bounds": { "maxDepth": 9 } })
        ));
    }
}
