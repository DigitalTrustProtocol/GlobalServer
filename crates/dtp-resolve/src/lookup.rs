//! Lookups (wot-model §8.1): one degree of stored winners, independent of
//! the observer. Incoming / outgoing / counts / batch and the neighborhood.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};

use dtp_graph::{Adj, BucketId, EdgeCols, EdgeId, Graph, NodeId, NodeType};
use dtp_model::{KIND_RATING, KIND_TRUST, Subject, SubjectType};

use crate::query::{Limits, ParamError, invalid, opt_bool, opt_str, opt_u64, parse_context};
use crate::results::{classify, connection_key, label_hints_json, subject_json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextMatch {
    Chain,
    Exact,
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    Recent,
    Author,
}

/// Subject classes for the outgoing `subjectTypes` filter.
fn subject_class(g: &Graph, node: NodeId, edge: &EdgeCols) -> &'static str {
    let info = g.node(node);
    match info.ty {
        NodeType::P if edge.kind == KIND_TRUST && !edge.person => "e",
        NodeType::P => "p",
        NodeType::E => "e",
        NodeType::I if info.is_bindable() => "user:id",
        NodeType::I if dtp_model::subject::twitter_post_id(&info.key.value()).is_some() => {
            "post:id"
        }
        NodeType::I => "other",
    }
}

/// Parsed lookup parameters.
#[derive(Clone, Debug)]
pub struct LookupParams {
    pub keys: Vec<String>,
    pub kinds: Vec<u32>,
    pub context: String,
    pub context_match: Option<ContextMatch>,
    pub values: Option<Vec<i8>>,
    pub subject_types: Option<Vec<String>>,
    pub labels: Vec<String>,
    pub include_inactive: bool,
    pub now: u64,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub raw: bool,
    pub merge_keys: bool,
    pub order: Order,
    pub limit: usize,
    pub cursor: Option<String>,
    pub with_totals: bool,
}

impl LookupParams {
    pub fn parse(
        params: &Map<String, Value>,
        limits: &Limits,
        server_now: u64,
    ) -> Result<LookupParams, ParamError> {
        let keys: Vec<String> = match params.get("keys") {
            Some(Value::Array(items)) if !items.is_empty() => items
                .iter()
                .map(|k| {
                    k.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| ParamError("keys must be strings".into()))
                })
                .collect::<Result<_, _>>()?,
            _ => return invalid("keys must be a non-empty array of wire node ids"),
        };
        if keys.len() > limits.max_lookup_keys {
            return invalid(format!(
                "keys exceeds maxLookupKeys ({})",
                limits.max_lookup_keys
            ));
        }
        for key in &keys {
            if Subject::from_wire_id(key).is_none() {
                return invalid(format!("key {key} is not a wire node id"));
            }
        }
        let kinds = match params.get("kinds") {
            None | Some(Value::Null) => vec![KIND_TRUST],
            Some(Value::Array(items)) if !items.is_empty() => {
                let mut kinds = Vec::new();
                for k in items {
                    match k.as_u64() {
                        Some(32009) => kinds.push(KIND_TRUST),
                        Some(32014) => kinds.push(KIND_RATING),
                        _ => return invalid("kinds must contain 32009 and/or 32014"),
                    }
                }
                kinds.sort_unstable();
                kinds.dedup();
                kinds
            }
            _ => return invalid("kinds must be a non-empty array"),
        };
        let context_match = match opt_str(params, "contextMatch")? {
            None => None,
            Some("chain") => Some(ContextMatch::Chain),
            Some("exact") => Some(ContextMatch::Exact),
            Some("any") => Some(ContextMatch::Any),
            Some(_) => return invalid("contextMatch must be chain, exact, or any"),
        };
        let values = match params.get("values") {
            None | Some(Value::Null) => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|v| match v.as_i64() {
                        Some(n @ -1..=1) => Ok(n as i8),
                        _ => invalid("values must be 1, 0, or -1"),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Some(_) => return invalid("values must be an array"),
        };
        let subject_types = match params.get("subjectTypes") {
            None | Some(Value::Null) => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|v| match v.as_str() {
                        Some(s @ ("p" | "user:id" | "post:id" | "e" | "other")) => {
                            Ok(s.to_string())
                        }
                        _ => invalid("subjectTypes must be p, user:id, post:id, e, or other"),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Some(_) => return invalid("subjectTypes must be an array"),
        };
        let labels = match params.get("labels") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            Some(_) => return invalid("labels must be an array"),
        };
        let raw = match opt_str(params, "mode")? {
            None | Some("selected") => false,
            Some("raw") => true,
            Some(_) => return invalid("mode must be selected or raw"),
        };
        let order = match opt_str(params, "order")? {
            None | Some("recent") => Order::Recent,
            Some("author") => Order::Author,
            Some(_) => return invalid("order must be recent or author"),
        };
        let limit = opt_u64(params, "limit")?
            .unwrap_or(100)
            .min(limits.max_lookup_page as u64) as usize;
        Ok(LookupParams {
            keys,
            kinds,
            context: parse_context(params, "context", "")?,
            context_match,
            values,
            subject_types,
            labels,
            include_inactive: opt_bool(params, "includeInactive")?,
            now: opt_u64(params, "now")?.unwrap_or(server_now),
            since: opt_u64(params, "since")?,
            until: opt_u64(params, "until")?,
            raw,
            merge_keys: opt_bool(params, "mergeKeys")?,
            order,
            limit,
            cursor: opt_str(params, "cursor")?.map(str::to_string),
            with_totals: opt_bool(params, "withTotals")?,
        })
    }

    fn fingerprint(&self, direction: Direction) -> String {
        let canonical = json!([
            direction == Direction::Incoming,
            self.keys,
            self.kinds,
            self.context,
            format!("{:?}", self.context_match),
            self.values,
            self.subject_types,
            self.labels,
            self.include_inactive,
            self.since,
            self.until,
            self.raw,
            self.merge_keys,
            format!("{:?}", self.order),
        ]);
        format!(
            "{:016x}",
            xxhash_rust::xxh3::xxh3_64(canonical.to_string().as_bytes())
        )
    }

    fn buckets(&self, g: &Graph, kind: u32) -> Vec<BucketId> {
        let default = if kind == KIND_RATING {
            ContextMatch::Exact
        } else {
            ContextMatch::Chain
        };
        match self.context_match.unwrap_or(default) {
            ContextMatch::Chain => g.contexts().chain(kind, &self.context),
            ContextMatch::Exact => g.contexts().get(kind, &self.context).into_iter().collect(),
            ContextMatch::Any => g.contexts().all_of_kind(kind),
        }
    }
}

/// One selected lookup record.
#[derive(Clone, Debug)]
struct Row {
    edge: EdgeId,
    author: NodeId,
    created_at: u64,
    id: [u8; 32],
    author_key: String,
}

struct Collected {
    rows: Vec<Row>,
    scanned: usize,
}

fn collect(
    g: &Graph,
    p: &LookupParams,
    direction: Direction,
    keys: &[String],
    limits: &Limits,
) -> Collected {
    let mut scanned = 0usize;
    // (group key) -> (bucket pos, edge)
    let mut groups: HashMap<(NodeId, NodeId, u32), (usize, EdgeId)> = HashMap::new();
    let mut raw_rows: Vec<EdgeId> = Vec::new();
    let mut consider =
        |g: &Graph, group: (NodeId, NodeId, u32), pos: usize, e: EdgeId, scanned: &mut usize| {
            *scanned += 1;
            let edge = g.edge(e);
            if !p.include_inactive && !edge.is_active_at(p.now) {
                return;
            }
            if p.raw {
                raw_rows.push(e);
                return;
            }
            match groups.get(&group) {
                None => {
                    groups.insert(group, (pos, e));
                }
                Some(&(cur_pos, cur)) if cur_pos == pos => {
                    if edge.tie_break(g.edge(cur)).is_lt() {
                        groups.insert(group, (pos, e));
                    }
                }
                Some(&(cur_pos, _)) if pos < cur_pos => {
                    groups.insert(group, (pos, e));
                }
                Some(_) => {}
            }
        };
    for (key_index, key) in keys.iter().enumerate() {
        let Some(subject) = Subject::from_wire_id(key) else {
            continue;
        };
        let Some(node) = g.node_id(&subject.node_key()) else {
            continue;
        };
        for &kind in &p.kinds {
            let buckets = p.buckets(g, kind);
            match direction {
                Direction::Incoming => {
                    let adj = Adj::incoming(kind);
                    for (pos, &b) in buckets.iter().enumerate() {
                        for (entry, e) in g.bucket(adj, node, b) {
                            consider(
                                g,
                                (entry.node(), key_index as NodeId, kind),
                                pos,
                                e,
                                &mut scanned,
                            );
                        }
                    }
                }
                Direction::Outgoing => {
                    if subject.ty != SubjectType::P {
                        continue;
                    }
                    let pos_of: HashMap<BucketId, usize> =
                        buckets.iter().enumerate().map(|(i, &b)| (b, i)).collect();
                    if kind == KIND_TRUST {
                        for (pos, &b) in buckets.iter().enumerate() {
                            for (entry, e) in g.bucket(Adj::TrustOut, node, b) {
                                consider(g, (node, entry.node(), kind), pos, e, &mut scanned);
                            }
                        }
                    }
                    for &e in g.other_out(node) {
                        let edge = g.edge(e);
                        if edge.kind != kind {
                            continue;
                        }
                        if let Some(&pos) = pos_of.get(&edge.bucket) {
                            consider(g, (node, edge.subject, kind), pos, e, &mut scanned);
                        }
                    }
                }
            }
        }
        if scanned > limits.max_lookup_records {
            break;
        }
    }
    let edges: Vec<EdgeId> = if p.raw {
        raw_rows
    } else {
        groups.into_values().map(|(_, e)| e).collect()
    };
    let mut seen: HashSet<EdgeId> = HashSet::new();
    let mut rows: Vec<Row> = edges
        .into_iter()
        .filter(|e| seen.insert(*e))
        .filter_map(|e| {
            let edge = g.edge(e);
            if let Some(values) = &p.values
                && let Some(v) = edge.trust_value()
                && !values.contains(&v)
            {
                return None;
            }
            if edge.kind == KIND_RATING
                && !p.labels.is_empty()
                && !p.labels.iter().any(|l| edge.labels().contains(l))
            {
                return None;
            }
            if p.since.is_some_and(|s| edge.created_at < s)
                || p.until.is_some_and(|u| edge.created_at > u)
            {
                return None;
            }
            if direction == Direction::Outgoing
                && let Some(types) = &p.subject_types
                && !types
                    .iter()
                    .any(|t| t == subject_class(g, edge.subject, edge))
            {
                return None;
            }
            Some(Row {
                edge: e,
                author: edge.author,
                created_at: edge.created_at,
                id: edge.id,
                author_key: g.node(edge.author).key.value(),
            })
        })
        .collect();
    if direction == Direction::Incoming && p.merge_keys {
        let pairs: HashSet<(NodeId, i8)> = rows
            .iter()
            .filter_map(|r| {
                let edge = g.edge(r.edge);
                (edge.kind == KIND_TRUST && g.node(edge.subject).ty == NodeType::P)
                    .then(|| (r.author, edge.trust_value().unwrap_or(0)))
            })
            .collect();
        rows.retain(|r| {
            let edge = g.edge(r.edge);
            let is_user = edge.kind == KIND_TRUST && g.node(edge.subject).is_bindable();
            !(is_user && pairs.contains(&(r.author, edge.trust_value().unwrap_or(0))))
        });
    }
    Collected { rows, scanned }
}

type SortKey = (String, std::cmp::Reverse<u64>, [u8; 32]);

fn sort_key(order: Order, r: &Row) -> SortKey {
    match order {
        Order::Recent => (String::new(), std::cmp::Reverse(r.created_at), r.id),
        Order::Author => (r.author_key.clone(), std::cmp::Reverse(r.created_at), r.id),
    }
}

fn encode_cursor(fingerprint: &str, key: &SortKey) -> String {
    let text = format!("{fingerprint}|{}|{}|{}", key.0, key.1.0, hex::encode(key.2));
    hex::encode(text)
}

fn decode_cursor(fingerprint: &str, cursor: &str) -> Result<SortKey, ParamError> {
    let bad = || ParamError("cursor is invalid or belongs to another query".into());
    let bytes = hex::decode(cursor).map_err(|_| bad())?;
    let text = String::from_utf8(bytes).map_err(|_| bad())?;
    let parts: Vec<&str> = text.split('|').collect();
    if parts.len() != 4 || parts[0] != fingerprint {
        return Err(bad());
    }
    let created: u64 = parts[2].parse().map_err(|_| bad())?;
    let id = dtp_model::hex32(parts[3]).ok_or_else(bad)?;
    Ok((parts[1].to_string(), std::cmp::Reverse(created), id))
}

/// Lookup item JSON (ResolvedStatement / RatingClaimEvidence fields minus
/// the walk-only ones).
pub fn item_json(g: &Graph, e: EdgeId) -> Value {
    let edge = g.edge(e);
    let mut item = Map::new();
    item.insert("eventId".into(), json!(edge.id_hex()));
    item.insert("connectionKey".into(), json!(connection_key(g, edge)));
    item.insert("kind".into(), json!(edge.kind));
    item.insert("author".into(), json!(g.node(edge.author).key.value()));
    item.insert(
        "subject".into(),
        subject_json(&g.node(edge.subject).subject()),
    );
    item.insert(
        "context".into(),
        json!(g.contexts().info(edge.bucket).context.to_string()),
    );
    match edge.value {
        dtp_model::RecordValue::Trust(v) => item.insert("value".into(), json!(v)),
        dtp_model::RecordValue::Score(s) => item.insert("score".into(), s.to_json()),
    };
    item.insert("createdAt".into(), json!(edge.created_at));
    if let Some(x) = edge.activate {
        item.insert("activeFrom".into(), json!(x));
    }
    if let Some(y) = edge.expire {
        item.insert("activeUntil".into(), json!(y));
    }
    if !edge.labels().is_empty() {
        item.insert("labels".into(), json!(edge.labels()));
    }
    if let Some(h) = label_hints_json(edge.label_hints()) {
        item.insert("labelHints".into(), h);
    }
    if !edge.content().is_empty() {
        item.insert("content".into(), json!(edge.content()));
    }
    Value::Object(item)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub trust: u64,
    pub neutral: u64,
    pub distrust: u64,
    pub ratings: u64,
}

impl Tally {
    fn add(&mut self, edge: &EdgeCols) {
        match edge.value {
            dtp_model::RecordValue::Trust(1) => self.trust += 1,
            dtp_model::RecordValue::Trust(-1) => self.distrust += 1,
            dtp_model::RecordValue::Trust(_) => self.neutral += 1,
            dtp_model::RecordValue::Score(_) => self.ratings += 1,
        }
    }

    pub fn to_json(self) -> Value {
        json!({ "trust": self.trust, "neutral": self.neutral, "distrust": self.distrust, "ratings": self.ratings })
    }
}

/// `lookup.incoming` / `lookup.outgoing`: one page.
pub fn lookup_page(
    g: &Graph,
    p: &LookupParams,
    direction: Direction,
    graph_version: u64,
    limits: &Limits,
) -> Result<Value, ParamError> {
    let fingerprint = p.fingerprint(direction);
    let after = p
        .cursor
        .as_deref()
        .map(|c| decode_cursor(&fingerprint, c))
        .transpose()?;
    let collected = collect(g, p, direction, &p.keys, limits);
    let budget_hit = collected.scanned > limits.max_lookup_records;
    let mut rows = collected.rows;
    let mut totals = Tally::default();
    for r in &rows {
        totals.add(g.edge(r.edge));
    }
    rows.sort_by_key(|r| sort_key(p.order, r));
    if let Some(after) = &after {
        rows.retain(|r| sort_key(p.order, r) > *after);
    }
    let has_more = rows.len() > p.limit;
    rows.truncate(p.limit);
    let mut out = Map::new();
    out.insert("graphVersion".into(), json!(graph_version));
    out.insert(
        "items".into(),
        Value::Array(rows.iter().map(|r| item_json(g, r.edge)).collect()),
    );
    if has_more && let Some(last) = rows.last() {
        out.insert(
            "nextCursor".into(),
            json!(encode_cursor(&fingerprint, &sort_key(p.order, last))),
        );
    }
    if budget_hit {
        out.insert("truncatedReasons".into(), json!(["edgeBudget"]));
    } else if p.with_totals {
        out.insert("totals".into(), totals.to_json());
    }
    Ok(Value::Object(out))
}

/// `lookup.counts`.
pub fn lookup_counts(
    g: &Graph,
    params: &Map<String, Value>,
    graph_version: u64,
    limits: &Limits,
    server_now: u64,
) -> Result<Value, ParamError> {
    let direction = match opt_str(params, "direction")? {
        Some("incoming") => Direction::Incoming,
        Some("outgoing") => Direction::Outgoing,
        _ => return invalid("direction must be incoming or outgoing"),
    };
    let p = LookupParams::parse(params, limits, server_now)?;
    let mut counts = Map::new();
    for key in &p.keys {
        let mut single = p.clone();
        single.merge_keys = false;
        let rows = collect(g, &single, direction, std::slice::from_ref(key), limits).rows;
        let mut tally = Tally::default();
        for r in &rows {
            tally.add(g.edge(r.edge));
        }
        counts.insert(key.clone(), tally.to_json());
    }
    if p.merge_keys && direction == Direction::Incoming {
        let rows = collect(g, &p, direction, &p.keys, limits).rows;
        let mut tally = Tally::default();
        for r in &rows {
            tally.add(g.edge(r.edge));
        }
        counts.insert("merged".into(), tally.to_json());
    }
    Ok(json!({ "graphVersion": graph_version, "counts": counts }))
}

/// `lookup.batch`.
pub fn lookup_batch(
    g: &Graph,
    params: &Map<String, Value>,
    graph_version: u64,
    limits: &Limits,
    server_now: u64,
) -> Result<Value, ParamError> {
    let Some(Value::Array(queries)) = params.get("queries") else {
        return invalid("queries must be an array");
    };
    if queries.len() > limits.max_lookup_batch {
        return invalid(format!(
            "queries exceeds maxLookupBatch ({})",
            limits.max_lookup_batch
        ));
    }
    let mut results = Map::new();
    let mut errors = Map::new();
    for q in queries {
        let Some(id) = q.get("id").and_then(Value::as_str) else {
            return invalid("every query needs a string id");
        };
        let empty = Map::new();
        let qp = q.get("params").and_then(Value::as_object).unwrap_or(&empty);
        let result = match q.get("op").and_then(Value::as_str) {
            Some("incoming") => LookupParams::parse(qp, limits, server_now)
                .and_then(|p| lookup_page(g, &p, Direction::Incoming, graph_version, limits)),
            Some("outgoing") => LookupParams::parse(qp, limits, server_now)
                .and_then(|p| lookup_page(g, &p, Direction::Outgoing, graph_version, limits)),
            Some("counts") => lookup_counts(g, qp, graph_version, limits, server_now),
            _ => Err(ParamError(
                "op must be incoming, outgoing, or counts".into(),
            )),
        };
        match result {
            Ok(v) => {
                results.insert(id.to_string(), v);
            }
            Err(e) => {
                errors.insert(id.to_string(), json!(format!("invalid: {e}")));
            }
        }
    }
    let mut out = Map::new();
    out.insert("graphVersion".into(), json!(graph_version));
    out.insert("results".into(), Value::Object(results));
    if !errors.is_empty() {
        out.insert("errors".into(), Value::Object(errors));
    }
    Ok(Value::Object(out))
}

/// `graph.neighborhood`: incoming + outgoing lookups for one center, shaped
/// as nodes and edges (node ids are `NodeId`s of this instance).
pub fn neighborhood(
    g: &Graph,
    params: &Map<String, Value>,
    graph_version: u64,
    limits: &Limits,
    server_now: u64,
) -> Result<Value, ParamError> {
    let center: Option<NodeId> = match params.get("centerId") {
        Some(Value::Number(n)) => {
            let id = n.as_u64().filter(|&id| (id as usize) < g.node_count());
            match id {
                Some(id) => Some(id as NodeId),
                None => return invalid("centerId is not a node of this instance"),
            }
        }
        Some(Value::String(s)) => match Subject::from_wire_id(s) {
            Some(subject) => g.node_id(&subject.node_key()),
            None => return invalid("centerId must be a number or a wire node id"),
        },
        Some(_) => return invalid("centerId must be a number or a wire node id"),
        None => match params
            .get("keys")
            .and_then(Value::as_array)
            .and_then(|k| k.first())
        {
            Some(Value::String(s)) => match Subject::from_wire_id(s) {
                Some(subject) => g.node_id(&subject.node_key()),
                None => return invalid("keys[0] must be a wire node id"),
            },
            _ => return invalid("centerId or keys is required"),
        },
    };
    let direction = opt_str(params, "direction")?.unwrap_or("both");
    if !matches!(direction, "in" | "out" | "both" | "incoming" | "outgoing") {
        return invalid("direction must be in, out, or both");
    }
    let values: Option<Vec<i8>> = match params.get("valueFilter") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s == "all" => None,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(v @ -1..=1) => Some(vec![v as i8]),
            _ => return invalid("valueFilter must be 1, 0, -1, an array of them, or all"),
        },
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(|v| match v.as_i64() {
                    Some(n @ -1..=1) => Ok(n as i8),
                    _ => invalid("valueFilter must contain 1, 0, or -1"),
                })
                .collect::<Result<_, _>>()?,
        ),
        Some(_) => return invalid("valueFilter must be 1, 0, -1, an array of them, or all"),
    };
    let limit = opt_u64(params, "limit")?.unwrap_or(100) as usize;
    let limit_capped = limit.min(limits.max_neighborhood_limit);
    let context = parse_context(params, "context", "identity")?;
    let Some(center) = center else {
        return Ok(
            json!({ "graphVersion": graph_version, "centerId": Value::Null, "truncated": false, "nodes": [], "edges": [] }),
        );
    };
    let center_info = g.node(center);
    let key = center_info.subject().wire_id();
    let base = LookupParams {
        keys: vec![key],
        kinds: vec![KIND_TRUST],
        context,
        context_match: None,
        values,
        subject_types: None,
        labels: vec![],
        include_inactive: false,
        now: opt_u64(params, "now")?.unwrap_or(server_now),
        since: None,
        until: None,
        raw: false,
        merge_keys: false,
        order: Order::Recent,
        limit: limit_capped,
        cursor: None,
        with_totals: false,
    };
    let mut rows: Vec<(Row, bool)> = Vec::new();
    if direction != "out" && direction != "outgoing" {
        rows.extend(
            collect(g, &base, Direction::Incoming, &base.keys, limits)
                .rows
                .into_iter()
                .map(|r| (r, true)),
        );
    }
    if direction != "in" && direction != "incoming" && center_info.ty == NodeType::P {
        rows.extend(
            collect(g, &base, Direction::Outgoing, &base.keys, limits)
                .rows
                .into_iter()
                .map(|r| (r, false)),
        );
    }
    rows.sort_by_key(|(r, _)| sort_key(Order::Recent, r));
    let truncated = rows.len() > limit_capped;
    rows.truncate(limit_capped);
    let mut node_ids: Vec<NodeId> = vec![center];
    let mut edges = Vec::new();
    for (r, _) in &rows {
        let edge = g.edge(r.edge);
        for n in [edge.author, edge.subject] {
            if !node_ids.contains(&n) {
                node_ids.push(n);
            }
        }
        edges.push(json!({
            "id": r.edge,
            "from": edge.author,
            "to": edge.subject,
            "value": edge.trust_value().unwrap_or(0),
            "context": g.contexts().info(edge.bucket).context.to_string(),
            "eventId": edge.id_hex(),
            "depth": 1,
        }));
    }
    let nodes: Vec<Value> = node_ids
        .iter()
        .map(|&n| {
            let info = g.node(n);
            let (kind, label) = classify(info);
            json!({
                "id": n,
                "kind": kind,
                "depth": if n == center { 0 } else { 1 },
                "label": label,
                "subject": subject_json(&info.subject()),
            })
        })
        .collect();
    let mut out = Map::new();
    out.insert("graphVersion".into(), json!(graph_version));
    out.insert("centerId".into(), json!(center));
    out.insert("truncated".into(), json!(truncated));
    out.insert("nodes".into(), Value::Array(nodes));
    out.insert("edges".into(), Value::Array(edges));
    if truncated {
        out.insert("truncatedReasons".into(), json!(["neighborhoodLimit"]));
    }
    Ok(Value::Object(out))
}
