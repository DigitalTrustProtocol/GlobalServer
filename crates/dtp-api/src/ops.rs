//! `DTP` operations that read a graph snapshot (resolver-api § Operations).
//! Session operations (`session.update`, `subscribe`, `unsubscribe`) live in
//! the connection because they change connection state.

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use dtp_graph::Graph;
use dtp_model::{KIND_RATING, KIND_TRUST};
use dtp_resolve::lookup::{
    Direction, LookupParams, lookup_batch, lookup_counts, lookup_page, neighborhood,
};
use dtp_resolve::{
    ExecCtx, ParamError, ResolveQuery, execute_batch, execute_rating, execute_trust, merge_defaults,
};

use crate::state::AppState;

/// A `DTP-ERR` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpError {
    pub code: &'static str,
    pub message: String,
}

impl OpError {
    pub fn invalid(message: impl Into<String>) -> OpError {
        OpError {
            code: "invalid",
            message: message.into(),
        }
    }
}

impl From<ParamError> for OpError {
    fn from(e: ParamError) -> Self {
        OpError::invalid(e.0)
    }
}

/// Operations executed on the blocking pool.
pub fn is_graph_op(op: &str) -> bool {
    matches!(
        op,
        "info"
            | "trust.query"
            | "trust.batch"
            | "rating.query"
            | "rating.batch"
            | "graph.field"
            | "lookup.incoming"
            | "lookup.outgoing"
            | "lookup.counts"
            | "lookup.batch"
            | "graph.neighborhood"
            | "graph.frontier"
            | "identity.claims"
    )
}

fn count_guardrails(state: &AppState, result: &Value) {
    let hit = |v: &Value| {
        for r in v
            .get("truncatedReasons")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(r) = r.as_str() {
                state.metrics.guardrail(r);
            }
        }
    };
    hit(result);
    if let Some(results) = result.get("results").and_then(Value::as_object) {
        for v in results.values() {
            hit(v);
        }
    }
    if let Some(errors) = result.get("errors").and_then(Value::as_object)
        && errors.values().any(|e| e == "timeout")
    {
        state.metrics.guardrail("timeBudget");
    }
}

/// Runs one graph operation.
pub fn execute(
    state: &AppState,
    graph: &Graph,
    op: &str,
    params: &Map<String, Value>,
    defaults: &Map<String, Value>,
) -> Result<Value, OpError> {
    let limits = &state.limits;
    let now = state.server_now();
    let version = graph.epoch();
    // Server defaults (config `[model]`) sit under the session defaults.
    let mut layered = Map::new();
    layered.insert("bindingMode".into(), json!(state.config.model.binding_mode));
    layered.insert(
        "followTrustThreshold".into(),
        json!(state.config.model.follow_trust_threshold),
    );
    layered.insert(
        "followTrustRed".into(),
        json!(state.config.model.follow_trust_red),
    );
    // Default score context per query type (resolver-api § Query fields).
    if op.starts_with("trust.") {
        layered.insert("context".into(), json!("identity"));
    }
    let defaults = &merge_defaults(&layered, defaults);
    let ctx = ExecCtx::new(version, limits);
    let result = match op {
        "info" => {
            let stats = graph.stats();
            let mut info = state.dtp_info();
            info["graphVersion"] = json!(version);
            info["memory"] = json!({
                "status": "ok",
                "graphBytes": stats.hot_bytes + stats.cold_bytes + stats.core_bytes,
            });
            info
        }
        "trust.query" | "rating.query" => {
            let merged = merge_defaults(defaults, params);
            let q = ResolveQuery::parse(&merged, limits, now)?;
            state.touch_root(&q.root);
            if op == "trust.query" {
                execute_trust(graph, &q, &ctx)
            } else {
                execute_rating(graph, &q, &ctx)
            }
        }
        "trust.batch" | "rating.batch" => {
            let merged = merge_defaults(defaults, params);
            let Some(Value::Array(items)) = params.get("items") else {
                return Err(OpError::invalid("items must be an array"));
            };
            let deadline = Instant::now() + Duration::from_millis(limits.batch_deadline_ms);
            let kind = if op == "trust.batch" {
                KIND_TRUST
            } else {
                KIND_RATING
            };
            if let Some(root) = merged.get("rootPubkey").and_then(Value::as_str) {
                state.touch_root(&root.to_ascii_lowercase());
            }
            execute_batch(graph, &merged, items, kind, &ctx, now, Some(deadline))?
        }
        "graph.field" => {
            let merged = merge_defaults(defaults, params);
            dtp_resolve::frontier::field(graph, &merged, version, limits, now)?
        }
        "lookup.incoming" | "lookup.outgoing" => {
            let p = LookupParams::parse(params, limits, now)?;
            let dir = if op == "lookup.incoming" {
                Direction::Incoming
            } else {
                Direction::Outgoing
            };
            lookup_page(graph, &p, dir, version, limits)?
        }
        "lookup.counts" => lookup_counts(graph, params, version, limits, now)?,
        "lookup.batch" => lookup_batch(graph, params, version, limits, now)?,
        "graph.neighborhood" => neighborhood(graph, params, version, limits, now)?,
        "graph.frontier" => dtp_resolve::frontier::frontier(graph, params, version, now)?,
        "identity.claims" => {
            let Some(twitter_id) = params.get("twitterId").and_then(Value::as_str) else {
                return Err(OpError::invalid("twitterId must be a string of digits"));
            };
            if !dtp_model::grammar::is_digits(twitter_id) {
                return Err(OpError::invalid("twitterId must be a string of digits"));
            }
            let claims: Vec<Value> = graph
                .claims_for(twitter_id)
                .into_iter()
                .map(|(p, id)| json!({ "pubkey": graph.node(p).key.value(), "eventId": hex::encode(id) }))
                .collect();
            json!({ "graphVersion": version, "claims": claims })
        }
        other => return Err(OpError::invalid(format!("unknown op {other}"))),
    };
    count_guardrails(state, &result);
    Ok(result)
}
