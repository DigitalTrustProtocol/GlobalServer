//! Trust and rating results, shaped exactly like the TypeScript DTOs
//! (`TrustQueryResult`, `RatingQueryResult`; `src/graph/query.ts`,
//! `src/graph/ratings/ArtifactRatingResolver.ts`) plus the additive fields of
//! resolver-api.md.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use dtp_graph::{EdgeCols, EdgeId, Graph, NodeId, NodeInfo, NodeType};
use dtp_model::score::resolution;
use dtp_model::{KIND_RATING, KIND_TRUST, Subject};

use crate::field::Field;
use crate::query::{Limits, ResolveQuery};
use crate::walk::{
    BindOutcome, BindingMode, Budgets, OwnEvidence, OwnSource, WalkOutcome, WalkParams, Walker,
};

/// Own evidence input (conformance only; servers never have any).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnInput {
    pub root: String,
    pub i_key: String,
    pub pubkey: String,
    pub source: OwnSource,
}

/// Execution context shared by the operations of one request.
#[derive(Clone, Debug)]
pub struct ExecCtx<'a> {
    pub graph_version: u64,
    pub limits: &'a Limits,
    pub own: &'a [OwnInput],
    /// Absolute deadline for this operation (`None`: unlimited).
    pub deadline: Option<Instant>,
    /// Node / record budgets (default: the limits).
    pub budgets: Option<(usize, usize)>,
}

impl<'a> ExecCtx<'a> {
    pub fn new(graph_version: u64, limits: &'a Limits) -> ExecCtx<'a> {
        ExecCtx {
            graph_version,
            limits,
            own: &[],
            deadline: None,
            budgets: None,
        }
    }

    fn budgets(&self, q: &ResolveQuery) -> Budgets {
        let (max_nodes, max_records) = self
            .budgets
            .unwrap_or((self.limits.max_reached_nodes, self.limits.max_walk_records));
        let op = Instant::now() + Duration::from_millis(q.deadline_ms);
        let deadline = match self.deadline {
            Some(d) => Some(d.min(op)),
            None if q.deadline_ms > 0 => Some(op),
            None => None,
        };
        Budgets {
            max_nodes,
            max_records,
            deadline,
        }
    }
}

/// `classifyTrustSubject` kind and label (display only).
pub fn classify(info: &NodeInfo) -> (&'static str, String) {
    let value = info.key.value();
    match info.ty {
        NodeType::P => ("pubkey", format!("{}…", &value[..value.len().min(12)])),
        NodeType::E => (
            "post",
            format!("Event · {}…", &value[..value.len().min(12)]),
        ),
        NodeType::I => {
            if let Some(id) = value.strip_prefix("user:id:") {
                ("twitter_id", format!("X · {id}"))
            } else if let Some(id) = value.strip_prefix("post:id:") {
                ("post", format!("Post · {id}"))
            } else {
                let short: String = value.chars().take(24).collect();
                ("other", format!("i:{short}"))
            }
        }
    }
}

pub fn subject_json(subject: &Subject) -> Value {
    json!({ "type": subject.ty.as_str(), "value": subject.value })
}

/// `"<kind>:<author>:<d>"`
pub fn connection_key(g: &Graph, edge: &EdgeCols) -> String {
    format!(
        "{}:{}:{}",
        edge.kind,
        g.node(edge.author).key.value(),
        edge.d.value()
    )
}

pub fn label_hints_json(hints: &[(String, String)]) -> Option<Value> {
    let map: Map<String, Value> = hints
        .iter()
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    (!map.is_empty()).then_some(Value::Object(map))
}

fn own_evidence(g: &Graph, ctx: &ExecCtx, root: &str) -> Vec<OwnEvidence> {
    ctx.own
        .iter()
        .filter(|o| o.root == root)
        .filter_map(|o| {
            Some(OwnEvidence {
                x: g.node_id(&o.i_key)?,
                pubkey: g.node_id(&o.pubkey)?,
                source: o.source,
            })
        })
        .collect()
}

/// Hop threshold of a query kind: the green knob for trust, 1 for ratings
/// (product profile `attention`).
pub fn threshold_for(kind: u32, q: &ResolveQuery) -> u64 {
    if kind == KIND_RATING { 1 } else { q.green }
}

fn walk(
    g: &Graph,
    q: &ResolveQuery,
    ctx: &ExecCtx,
    kind: u32,
    threshold: u64,
) -> Option<WalkOutcome> {
    Some(Walker::new(g, walk_params(g, q, ctx, kind, threshold)?).run())
}

/// Walk inputs for a query (`None` when the root is not in the graph).
pub fn walk_params(
    g: &Graph,
    q: &ResolveQuery,
    ctx: &ExecCtx,
    kind: u32,
    threshold: u64,
) -> Option<WalkParams> {
    let root = g.node_id(&q.root)?;
    let contexts = g.contexts();
    Some(WalkParams {
        root,
        subject: g.node_id(&q.subject.node_key()),
        kind,
        hop_buckets: contexts.chain(KIND_TRUST, &q.hop_context),
        score_buckets: contexts.chain(kind, &q.context),
        threshold,
        max_depth: q.max_depth,
        now: q.now,
        mode: q.mode,
        own: own_evidence(g, ctx, &q.root),
        budgets: ctx.budgets(q),
        track_contrib: q.format_path,
    })
}

/// Result for a query answered from a root field (see [`crate::field`]).
pub fn from_field(
    g: &Graph,
    q: &ResolveQuery,
    ctx: &ExecCtx,
    kind: u32,
    field: &mut Field,
) -> Value {
    let buckets = g.contexts().chain(kind, &q.context);
    let outcome = field.resolve(g.node_id(&q.subject.node_key()), kind, &buckets);
    if kind == KIND_RATING {
        rating_result(g, q, ctx, Some(outcome))
    } else {
        trust_result(g, q, ctx, Some(outcome))
    }
}

/// `binding` provenance for `user:id` subjects.
fn binding_json(g: &Graph, mode: BindingMode, bind: Option<&BindOutcome>) -> Value {
    let mut out = Map::new();
    out.insert("mode".into(), json!(mode.as_str()));
    match bind.and_then(|b| b.bind.as_ref()) {
        Some(b) => {
            out.insert("pubkey".into(), json!(g.node(b.pubkey).key.value()));
            out.insert("source".into(), json!(b.source.as_str()));
            out.insert("confirmed".into(), json!(b.claim.is_some()));
            if let Some(w) = b.witness {
                out.insert("witnessEventId".into(), json!(g.edge(w).id_hex()));
            }
            if let Some(level) = b.witness_level {
                out.insert("witnessDegree".into(), json!(u64::from(level) + 1));
            }
            if let Some(c) = b.claim {
                out.insert("claimEventId".into(), json!(hex::encode(c)));
            }
        }
        None => {
            out.insert("source".into(), json!("none"));
            out.insert("confirmed".into(), json!(false));
            if mode == BindingMode::Strict
                && let Some(cut) = bind.and_then(|b| b.cut.as_ref())
            {
                out.insert("cutCandidate".into(), json!(g.node(cut.pubkey).key.value()));
                out.insert("cutReason".into(), json!(cut.reason));
            }
        }
    }
    Value::Object(out)
}

fn is_user_id(subject: &Subject) -> bool {
    subject.ty == dtp_model::SubjectType::I
        && dtp_model::subject::twitter_account_id(&subject.node_key()).is_some()
}

/// Path view (model §7.2): backward union of contributing statements.
fn path_view(
    g: &Graph,
    outcome: &WalkOutcome,
    root: NodeId,
    subject_node: NodeId,
    evidence_edges: bool,
    max_nodes: usize,
) -> (Value, bool) {
    let mut nodes: Vec<(NodeId, u8)> = Vec::new();
    let mut node_seen: HashSet<NodeId> = HashSet::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut edge_seen: HashSet<EdgeId> = HashSet::new();
    let mut truncated = false;
    let level_of = |n: NodeId| -> u8 {
        if n == root {
            0
        } else {
            outcome.states.get(&n).map_or(0, |s| s.level)
        }
    };
    let mut add_node = |n: NodeId, depth: u8, nodes: &mut Vec<(NodeId, u8)>| -> bool {
        if node_seen.contains(&n) {
            return true;
        }
        if nodes.len() >= max_nodes {
            return false;
        }
        node_seen.insert(n);
        nodes.push((n, depth));
        true
    };
    let edge_json = |e: EdgeId, to: NodeId, depth: u8| -> Value {
        let edge = g.edge(e);
        json!({
            "id": e,
            "from": edge.author,
            "to": to,
            "value": edge.trust_value().unwrap_or(0),
            "context": g.contexts().info(edge.bucket).context.to_string(),
            "eventId": edge.id_hex(),
            "depth": depth,
        })
    };
    add_node(subject_node, outcome.degree, &mut nodes);
    let mut queue: VecDeque<NodeId> = VecDeque::new();
    for hit in &outcome.hits {
        if evidence_edges && edge_seen.insert(hit.edge) {
            edges.push(edge_json(hit.edge, subject_node, outcome.degree));
        }
        queue.push_back(hit.author);
    }
    let mut visited: HashSet<NodeId> = HashSet::new();
    while let Some(a) = queue.pop_front() {
        if !visited.insert(a) {
            continue;
        }
        if !add_node(a, level_of(a), &mut nodes) {
            truncated = true;
            break;
        }
        if a == root {
            continue;
        }
        for &e in outcome.contrib.get(&a).map_or(&[][..], |v| v.as_slice()) {
            if edge_seen.insert(e) {
                edges.push(edge_json(e, a, level_of(a)));
            }
            queue.push_back(g.edge(e).author);
        }
    }
    let nodes: Vec<Value> = nodes
        .into_iter()
        .map(|(n, depth)| {
            let info = g.node(n);
            let (kind, label) = classify(info);
            json!({
                "id": n,
                "kind": kind,
                "depth": depth,
                "label": label,
                "subject": subject_json(&info.subject()),
            })
        })
        .collect();
    (json!({ "nodes": nodes, "edges": edges }), truncated)
}

fn empty_path_view() -> Value {
    json!({ "nodes": [], "edges": [] })
}

fn truncation_fields(out: &mut Map<String, Value>, reasons: &[&str], complete_depth: Option<u8>) {
    if !reasons.is_empty() {
        out.insert("truncatedReasons".into(), json!(reasons));
    }
    if let Some(depth) = complete_depth {
        out.insert("completeDepth".into(), json!(depth));
    }
}

/// `trust.query` (kind 32009).
pub fn execute_trust(g: &Graph, q: &ResolveQuery, ctx: &ExecCtx) -> Value {
    trust_result(g, q, ctx, walk(g, q, ctx, KIND_TRUST, q.green))
}

/// Maps a walk (or field) outcome to `TrustQueryResult`.
pub fn trust_result(
    g: &Graph,
    q: &ResolveQuery,
    ctx: &ExecCtx,
    outcome: Option<WalkOutcome>,
) -> Value {
    let connected = outcome.as_ref().is_some_and(|o| o.connected);
    let degree = outcome.as_ref().map_or(0, |o| o.degree);

    let mut statements: Vec<(u64, String, Value, bool)> = Vec::new();
    let (mut trust, mut distrust, mut neutral) = (0u64, 0u64, 0u64);
    if let Some(o) = outcome.as_ref().filter(|o| o.connected) {
        let distance = u64::from(o.degree) - 1;
        let root_node = g.node_id(&q.root);
        for hit in &o.hits {
            let edge = g.edge(hit.edge);
            let value = edge.trust_value().unwrap_or(0);
            match value {
                1 => trust += 1,
                -1 => distrust += 1,
                _ => neutral += 1,
            }
            let context = g.contexts().info(edge.bucket).context.to_string();
            let context_match = if context == q.context {
                "exact"
            } else if context.is_empty() {
                "general"
            } else {
                "parent"
            };
            let mut s = Map::new();
            s.insert("eventId".into(), json!(edge.id_hex()));
            s.insert("connectionKey".into(), json!(connection_key(g, edge)));
            s.insert("author".into(), json!(g.node(edge.author).key.value()));
            s.insert("subject".into(), subject_json(&q.subject));
            s.insert("context".into(), json!(context));
            s.insert("requestedContext".into(), json!(q.context));
            s.insert("contextMatch".into(), json!(context_match));
            s.insert("value".into(), json!(value));
            s.insert("createdAt".into(), json!(edge.created_at));
            if let Some(x) = edge.activate {
                s.insert("activeFrom".into(), json!(x));
            }
            if let Some(y) = edge.expire {
                s.insert("activeUntil".into(), json!(y));
            }
            if !edge.content().is_empty() {
                s.insert("content".into(), json!(edge.content()));
            }
            if !edge.labels().is_empty() {
                s.insert("labels".into(), json!(edge.labels()));
            }
            if let Some(h) = label_hints_json(edge.label_hints()) {
                s.insert("labelHints".into(), h);
            }
            s.insert("distance".into(), json!(distance));
            let is_own = Some(edge.author) == root_node;
            statements.push((edge.created_at, edge.id_hex(), Value::Object(s), is_own));
        }
    }
    statements.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut source_ids: Vec<String> = statements.iter().map(|s| s.1.clone()).collect();
    source_ids.sort();
    source_ids.dedup();
    let direct = statements.iter().find(|s| s.3).map(|s| {
        let mut d = s.2.clone();
        d["distance"] = json!(0);
        d
    });
    let total = statements.len();
    let statements_truncated = total > q.statement_limit;
    let listed: Vec<Value> = statements
        .into_iter()
        .take(q.statement_limit)
        .map(|s| s.2)
        .collect();

    let mut reasons: Vec<&str> = Vec::new();
    let mut complete_depth = None;
    if let Some(reason) = outcome.as_ref().and_then(|o| o.truncated) {
        reasons.push(reason.as_str());
        complete_depth = outcome.as_ref().map(|o| o.complete_depth);
    }
    if statements_truncated {
        reasons.push("statementLimit");
    }
    let mut path = empty_path_view();
    if q.format_path
        && let Some(o) = outcome.as_ref().filter(|o| o.connected)
        && let (Some(root), Some(ns)) = (g.node_id(&q.root), o.subject_node)
    {
        let (view, cut) = path_view(g, o, root, ns, true, ctx.limits.max_path_nodes);
        path = view;
        if cut {
            reasons.push("pathLimit");
        }
    }

    let band = resolution(trust, distrust, connected, q.red, q.green);
    let mut out = Map::new();
    out.insert("subject".into(), subject_json(&q.subject));
    out.insert("context".into(), json!(q.context));
    out.insert("resolution".into(), json!(band.as_str()));
    out.insert("trust".into(), json!(trust));
    out.insert("distrust".into(), json!(distrust));
    if neutral > 0 {
        out.insert("neutral".into(), json!(neutral));
    }
    out.insert("trustValue".into(), json!(trust as i64 - distrust as i64));
    out.insert("degree".into(), json!(degree));
    out.insert("connected".into(), json!(connected));
    if let Some(d) = direct {
        out.insert("direct".into(), d);
    }
    out.insert("statements".into(), Value::Array(listed));
    out.insert("paths".into(), json!([]));
    out.insert("pathView".into(), path);
    out.insert("sourceEventIds".into(), json!(source_ids));
    out.insert("computedAt".into(), json!(q.now));
    out.insert("graphVersion".into(), json!(ctx.graph_version));
    out.insert("truncated".into(), json!(!reasons.is_empty()));
    out.insert("followTrustThreshold".into(), json!(q.green));
    out.insert("followTrustRed".into(), json!(q.red));
    truncation_fields(&mut out, &reasons, complete_depth);
    if statements_truncated {
        out.insert("statementsTruncated".into(), json!(true));
    }
    if is_user_id(&q.subject) {
        out.insert(
            "binding".into(),
            binding_json(
                g,
                q.mode,
                outcome.as_ref().and_then(|o| o.subject_bind.as_ref()),
            ),
        );
    }
    Value::Object(out)
}

/// Arithmetic mean like JavaScript (`reduce` sum / length); integral means
/// serialize without a fraction.
fn mean_json(scores: &[f64]) -> Value {
    if scores.is_empty() {
        return Value::Null;
    }
    let sum: f64 = scores.iter().sum();
    let mean = sum / scores.len() as f64;
    if mean.fract() == 0.0 && mean.abs() < 9.0e15 {
        json!(mean as i64)
    } else {
        json!(mean)
    }
}

/// `rating.query` (kind 32014; hop threshold fixed at 1).
pub fn execute_rating(g: &Graph, q: &ResolveQuery, ctx: &ExecCtx) -> Value {
    rating_result(g, q, ctx, walk(g, q, ctx, KIND_RATING, 1))
}

/// Maps a walk (or field) outcome to `RatingQueryResult`.
pub fn rating_result(
    g: &Graph,
    q: &ResolveQuery,
    ctx: &ExecCtx,
    outcome: Option<WalkOutcome>,
) -> Value {
    let mut claims: Vec<(u64, String, Value, NodeId, f64, EdgeId)> = Vec::new();
    if let Some(o) = outcome.as_ref().filter(|o| o.connected) {
        let distance = u64::from(o.degree) - 1;
        for hit in &o.hits {
            let edge = g.edge(hit.edge);
            let dtp_model::RecordValue::Score(score) = edge.value else {
                continue;
            };
            if !q.labels.is_empty() && !q.labels.iter().any(|l| edge.labels().contains(l)) {
                continue;
            }
            let mut c = Map::new();
            c.insert("eventId".into(), json!(edge.id_hex()));
            c.insert("author".into(), json!(g.node(edge.author).key.value()));
            c.insert(
                "subject".into(),
                subject_json(&g.node(edge.subject).subject()),
            );
            c.insert(
                "context".into(),
                json!(g.contexts().info(edge.bucket).context.to_string()),
            );
            c.insert("score".into(), score.to_json());
            c.insert("labels".into(), json!(edge.labels()));
            if let Some(h) = label_hints_json(edge.label_hints()) {
                c.insert("labelHints".into(), h);
            }
            c.insert("content".into(), json!(edge.content()));
            c.insert("createdAt".into(), json!(edge.created_at));
            if let Some(x) = edge.activate {
                c.insert("activeFrom".into(), json!(x));
            }
            if let Some(y) = edge.expire {
                c.insert("activeUntil".into(), json!(y));
            }
            c.insert("distance".into(), json!(distance));
            claims.push((
                edge.created_at,
                edge.id_hex(),
                Value::Object(c),
                edge.author,
                score.as_f64(),
                hit.edge,
            ));
        }
    }
    claims.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let connected = !claims.is_empty();
    let degree = if connected {
        outcome.as_ref().map_or(0, |o| o.degree)
    } else {
        0
    };
    let scores: Vec<f64> = claims.iter().map(|c| c.4).collect();
    let root_node = g.node_id(&q.root);
    let own = claims
        .iter()
        .find(|c| Some(c.3) == root_node)
        .map(|c| c.2.clone());
    let mut source_ids: Vec<String> = claims.iter().map(|c| c.1.clone()).collect();
    source_ids.sort();
    let claim_count = claims.len();
    let statements_truncated = claim_count > q.statement_limit;

    let mut reasons: Vec<&str> = Vec::new();
    let mut complete_depth = None;
    if !connected && let Some(reason) = outcome.as_ref().and_then(|o| o.truncated) {
        reasons.push(reason.as_str());
        complete_depth = outcome.as_ref().map(|o| o.complete_depth);
    }
    if statements_truncated {
        reasons.push("statementLimit");
    }

    let mut path = empty_path_view();
    let mut rating_edges: Vec<Value> = Vec::new();
    if q.format_path
        && connected
        && let Some(o) = outcome.as_ref()
        && let (Some(root), Some(ns)) = (root_node, o.subject_node)
    {
        let kept: HashSet<EdgeId> = claims.iter().map(|c| c.5).collect();
        let mut filtered = o.clone();
        filtered.hits.retain(|h| kept.contains(&h.edge));
        let (view, cut) = path_view(g, &filtered, root, ns, false, ctx.limits.max_path_nodes);
        path = view;
        if cut {
            reasons.push("pathLimit");
        }
        let mut seen_from: HashSet<NodeId> = HashSet::new();
        for c in &claims {
            if !seen_from.insert(c.3) {
                continue;
            }
            let edge = g.edge(c.5);
            let value = if c.4 >= 50.0 { 1 } else { -1 };
            rating_edges.push(json!({
                "id": edge.id_hex(),
                "from": c.3,
                "to": ns,
                "value": value,
                "context": g.contexts().info(edge.bucket).context.to_string(),
                "eventId": edge.id_hex(),
                "depth": degree,
            }));
        }
    }

    let mut out = Map::new();
    out.insert("subject".into(), subject_json(&q.subject));
    out.insert("context".into(), json!(q.context));
    out.insert(
        "claims".into(),
        Value::Array(
            claims
                .iter()
                .take(q.statement_limit)
                .map(|c| c.2.clone())
                .collect(),
        ),
    );
    out.insert("averageScore".into(), mean_json(&scores));
    out.insert("claimCount".into(), json!(claim_count));
    out.insert("degree".into(), json!(degree));
    if let Some(own) = own {
        out.insert("own".into(), own);
    }
    out.insert("sourceEventIds".into(), json!(source_ids));
    out.insert("paths".into(), json!([]));
    out.insert("pathView".into(), path);
    out.insert("ratingEdges".into(), Value::Array(rating_edges));
    out.insert("computedAt".into(), json!(q.now));
    out.insert("graphVersion".into(), json!(ctx.graph_version));
    out.insert("followTrustThreshold".into(), json!(q.green));
    out.insert("followTrustRed".into(), json!(q.red));
    if !reasons.is_empty() {
        out.insert("truncated".into(), json!(true));
    }
    truncation_fields(&mut out, &reasons, complete_depth);
    if statements_truncated {
        out.insert("statementsTruncated".into(), json!(true));
    }
    if is_user_id(&q.subject) {
        out.insert(
            "binding".into(),
            binding_json(
                g,
                q.mode,
                outcome.as_ref().and_then(|o| o.subject_bind.as_ref()),
            ),
        );
    }
    Value::Object(out)
}

/// Batch execution (`trust.batch` / `rating.batch`): each item is the shared
/// query plus its own `subject` / `context` / `labels`.
pub fn execute_batch(
    g: &Graph,
    shared: &Map<String, Value>,
    items: &[Value],
    kind: u32,
    ctx: &ExecCtx,
    server_now: u64,
    batch_deadline: Option<Instant>,
) -> Result<Value, crate::query::ParamError> {
    if items.len() > ctx.limits.max_batch_items {
        return crate::query::invalid(format!(
            "items exceeds maxBatchItems ({})",
            ctx.limits.max_batch_items
        ));
    }
    let mut results = Map::new();
    let mut errors = Map::new();
    let mut seen: HashMap<String, ()> = HashMap::new();
    // Items share root, hop context, threshold, depth, mode, and `now`
    // (only subject / context / labels vary), so one root field serves every
    // eligible item: one walk plus a hit test per item.
    let mut field: Option<Option<Field>> = None;
    for item in items {
        let Some(obj) = item.as_object() else {
            return crate::query::invalid("items must be objects");
        };
        let Some(key) = obj.get("key").and_then(Value::as_str) else {
            return crate::query::invalid("every item needs a string key");
        };
        if seen.insert(key.to_string(), ()).is_some() {
            return crate::query::invalid(format!("duplicate item key {key}"));
        }
        if batch_deadline.is_some_and(|d| Instant::now() >= d) {
            errors.insert(key.to_string(), json!("timeout"));
            continue;
        }
        let mut params = shared.clone();
        params.remove("items");
        for field in ["subject", "context", "labels"] {
            if let Some(v) = obj.get(field) {
                params.insert(field.into(), v.clone());
            }
        }
        match ResolveQuery::parse(&params, ctx.limits, server_now) {
            Ok(q) => {
                let built = field.get_or_insert_with(|| {
                    walk_params(g, &q, ctx, kind, threshold_for(kind, &q))
                        .map(|p| Field::build(g, p, &q.hop_context))
                });
                let result = match built {
                    Some(f) if !q.format_path && f.serves(kind, &q.context) => {
                        from_field(g, &q, ctx, kind, f)
                    }
                    _ if kind == KIND_RATING => execute_rating(g, &q, ctx),
                    _ => execute_trust(g, &q, ctx),
                };
                results.insert(key.to_string(), result);
            }
            Err(e) => {
                errors.insert(key.to_string(), json!(format!("invalid: {e}")));
            }
        }
    }
    let mut out = Map::new();
    out.insert("graphVersion".into(), json!(ctx.graph_version));
    out.insert("results".into(), Value::Object(results));
    if !errors.is_empty() {
        out.insert("errors".into(), Value::Object(errors));
    }
    Ok(Value::Object(out))
}
