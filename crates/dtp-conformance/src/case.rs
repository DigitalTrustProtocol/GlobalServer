//! Model cases: records + claims + own evidence (+ ops) → query expectations,
//! and the model properties of conformance.md § Properties.

use serde_json::{Map, Value, json};

use dtp_graph::Graph;
use dtp_model::{
    Deletion, DeletionTarget, EdgeRecord, KIND_RATING, KIND_TRUST, RecordValue, ScoreMicro,
    SubjectType,
};
use dtp_resolve::lookup::{Direction, LookupParams, lookup_counts, lookup_page, neighborhood};
use dtp_resolve::{
    ExecCtx, Limits, OwnInput, OwnSource, ResolveQuery, execute_batch, execute_rating,
    execute_trust,
};

use crate::canon::{canonicalize, compare};

/// Outcome of one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseOutcome {
    Pass,
    Fail(Vec<String>),
    Skip(String),
}

const NOW: u64 = 1_000_000;

struct Setup {
    graph: Graph,
    own: Vec<OwnInput>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Natural,
    Reversed,
    Shuffled(u64),
    Doubled,
}

fn limits() -> Limits {
    Limits {
        operation_deadline_ms: 0,
        batch_deadline_ms: 0,
        ..Limits::protocol_defaults()
    }
}

fn str_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_str))
}

fn u64_field(v: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_u64))
}

/// Builds an `EdgeRecord` from a corpus record (missing fields get
/// deterministic defaults — a local extension).
pub fn record_from(v: &Value, index: usize) -> Result<EdgeRecord, String> {
    let pubkey = str_field(v, &["pubkey", "author"])
        .ok_or("record without pubkey")?
        .to_lowercase();
    let kind = u64_field(v, &["kind"]).unwrap_or(u64::from(KIND_TRUST)) as u32;
    let subject = dtp_model::subject::normalize_key(
        str_field(v, &["subject"]).ok_or("record without subject")?,
    );
    let subject_type = match str_field(v, &["subjectType"]) {
        Some(t) => SubjectType::parse(t).ok_or(format!("bad subjectType {t}"))?,
        None if dtp_model::is_hex64(&subject) => SubjectType::P,
        None => SubjectType::I,
    };
    let context = str_field(v, &["context", "c_tag"])
        .unwrap_or("")
        .to_string();
    let hint = str_field(v, &["hintPubkey"]).map(str::to_lowercase);
    let scope_rank =
        u64_field(v, &["scopeRank"]).unwrap_or(if hint.is_some() { 2 } else { 1 }) as u8;
    let created_at = u64_field(v, &["created_at", "createdAt"]).unwrap_or(100 + index as u64);
    let id = str_field(v, &["id", "eventId"])
        .map(str::to_string)
        .unwrap_or_else(|| {
            dtp_model::sha256_hex(&format!(
                "record-{index}-{pubkey}-{subject}-{context}-{created_at}"
            ))
        });
    let d = match str_field(v, &["addressKey"]) {
        Some(key) => {
            let mut parts = key.splitn(3, ':');
            let _kind = parts.next();
            let _author = parts.next();
            parts.next().unwrap_or("").to_string()
        }
        None => str_field(v, &["dTag", "d"])
            .map(str::to_string)
            // Corpus default: "<kind>:<pubkey>:<subjectType>:<subject>:<context>".
            .unwrap_or_else(|| format!("{}:{subject}:{context}", subject_type.as_str())),
    };
    let value = match v.get("value").or_else(|| v.get("score")) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(val) => {
            if kind == KIND_RATING {
                let f = val
                    .as_f64()
                    .or_else(|| val.as_str().and_then(|s| s.parse().ok()))
                    .ok_or("bad score")?;
                Some(RecordValue::Score(ScoreMicro(
                    (f * 1_000_000.0).round() as u32
                )))
            } else {
                let n = val
                    .as_i64()
                    .or_else(|| val.as_str().and_then(|s| s.parse().ok()))
                    .ok_or("bad value")?;
                Some(RecordValue::Trust(n.clamp(-1, 1) as i8))
            }
        }
    };
    let labels: Vec<String> = v
        .get("labels")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|l| l.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let label_hints: Vec<(String, String)> = v
        .get("labelHints")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Ok(EdgeRecord {
        id,
        pubkey,
        kind,
        created_at,
        d,
        subject_type,
        subject,
        context,
        value,
        activate: u64_field(v, &["activate", "activeFrom"]),
        expire: u64_field(v, &["expire", "activeUntil"]),
        scope_rank,
        hint_pubkey: hint,
        content: str_field(v, &["content"]).unwrap_or("").to_string(),
        labels,
        label_hints,
    })
}

fn own_from(v: &Value) -> Result<OwnInput, String> {
    Ok(OwnInput {
        root: str_field(v, &["root"])
            .ok_or("ownEvidence without root")?
            .to_lowercase(),
        i_key: str_field(v, &["iKey"])
            .ok_or("ownEvidence without iKey")?
            .to_lowercase(),
        pubkey: str_field(v, &["pubkey"])
            .ok_or("ownEvidence without pubkey")?
            .to_lowercase(),
        source: match str_field(v, &["source"]) {
            Some("post") => OwnSource::Post,
            _ => OwnSource::Bio,
        },
    })
}

fn apply_claim(g: &mut Graph, v: &Value, index: usize) -> Result<(), String> {
    let pubkey = str_field(v, &["pubkey"])
        .ok_or("claim without pubkey")?
        .to_lowercase();
    let twitter = str_field(v, &["twitterId"])
        .ok_or("claim without twitterId")?
        .to_string();
    // Several claims by one pubkey accumulate (the corpus lists pairs).
    let mut ids: Vec<std::sync::Arc<str>> = g
        .node_id(&pubkey)
        .and_then(|p| g.claim_slot(p))
        .and_then(|s| s.winner.as_ref())
        .map(|w| w.twitter_ids.clone())
        .unwrap_or_default();
    if !ids.iter().any(|x| **x == *twitter) {
        ids.push(twitter.as_str().into());
    }
    let id = str_field(v, &["eventId", "id"])
        .map(str::to_string)
        .unwrap_or_else(|| dtp_model::sha256_hex(&format!("claim-{pubkey}-{}", ids.len())));
    let created_at =
        u64_field(v, &["created_at"]).unwrap_or(1 + index as u64 + ids.len() as u64 * 1_000);
    g.apply_claim_ids(&pubkey, &id, created_at, ids);
    Ok(())
}

fn apply_op(setup: &mut Setup, op: &Value, index: usize) -> Result<(), String> {
    let name = str_field(op, &["op", "type"]).ok_or("op without name")?;
    let body = op
        .get("record")
        .or_else(|| op.get("claim"))
        .or_else(|| op.get("evidence"))
        .unwrap_or(op);
    match name {
        "apply" => {
            setup.graph.apply_record(&record_from(body, index)?);
        }
        "remove" => {
            let key = str_field(body, &["addressKey"]).ok_or("remove without addressKey")?;
            let mut parts = key.splitn(3, ':');
            let kind: u32 = parts
                .next()
                .and_then(|k| k.parse().ok())
                .ok_or("bad addressKey")?;
            let author = parts.next().ok_or("bad addressKey")?;
            let d = parts.next().ok_or("bad addressKey")?;
            setup.graph.remove_slot(kind, author, d);
        }
        "claim" => apply_claim(&mut setup.graph, body, index)?,
        "unclaim" => {
            let pubkey = str_field(body, &["pubkey"]).ok_or("unclaim without pubkey")?;
            setup.graph.remove_claim(&pubkey.to_lowercase());
        }
        "own" => setup.own.push(own_from(body)?),
        "unown" => {
            let o = own_from(body)?;
            setup
                .own
                .retain(|x| !(x.root == o.root && x.i_key == o.i_key));
        }
        "delete" => {
            let pubkey = str_field(body, &["author", "pubkey"])
                .ok_or("delete without author")?
                .to_lowercase();
            let mut targets = Vec::new();
            if let Some(id) = str_field(body, &["eventId"]) {
                targets.push(DeletionTarget::Event(id.to_lowercase()));
            }
            if let Some(key) = str_field(body, &["addressKey"]) {
                let mut parts = key.splitn(3, ':');
                let kind = parts.next().and_then(|k| k.parse().ok()).unwrap_or(0);
                let pk = parts.next().unwrap_or("").to_lowercase();
                let d = parts.next().unwrap_or("").to_string();
                targets.push(DeletionTarget::Address {
                    kind,
                    pubkey: pk,
                    d,
                });
            }
            for e in body
                .get("e")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                targets.push(DeletionTarget::Event(
                    e.as_str().unwrap_or("").to_lowercase(),
                ));
            }
            for a in body
                .get("a")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let mut parts = a.as_str().unwrap_or("").splitn(3, ':');
                let kind = parts.next().and_then(|k| k.parse().ok()).unwrap_or(0);
                let pk = parts.next().unwrap_or("").to_string();
                let d = parts.next().unwrap_or("").to_string();
                targets.push(DeletionTarget::Address {
                    kind,
                    pubkey: pk,
                    d,
                });
            }
            let deletion = Deletion {
                id: dtp_model::sha256_hex(&format!("deletion-{index}")),
                pubkey,
                created_at: u64_field(body, &["created_at"]).unwrap_or(0),
                targets,
                kinds: vec![],
            };
            setup.graph.apply_deletion(&deletion);
        }
        other => return Err(format!("unknown op {other}")),
    }
    Ok(())
}

fn permute<T: Clone>(items: &[T], order: Order) -> Vec<T> {
    match order {
        Order::Natural => items.to_vec(),
        Order::Reversed => items.iter().rev().cloned().collect(),
        Order::Doubled => items.iter().chain(items.iter()).cloned().collect(),
        Order::Shuffled(seed) => {
            let mut v = items.to_vec();
            let mut state = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            for i in (1..v.len()).rev() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let j = (state >> 33) as usize % (i + 1);
                v.swap(i, j);
            }
            v
        }
    }
}

fn build(case: &Value, order: Order) -> Result<Setup, String> {
    let mut setup = Setup {
        graph: Graph::new(),
        own: Vec::new(),
    };
    if let Some(ops) = case.get("ops").and_then(Value::as_array) {
        for (i, op) in ops.iter().enumerate() {
            apply_op(&mut setup, op, i)?;
        }
        return Ok(setup);
    }
    let records: Vec<(usize, Value)> = case
        .get("records")
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().enumerate().collect())
        .unwrap_or_default();
    for (i, r) in permute(&records, order) {
        setup.graph.apply_record(&record_from(&r, i)?);
    }
    let claims: Vec<(usize, Value)> = case
        .get("claims")
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().enumerate().collect())
        .unwrap_or_default();
    for (i, c) in permute(&claims, order) {
        apply_claim(&mut setup.graph, &c, i)?;
    }
    for o in case
        .get("ownEvidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        setup.own.push(own_from(o)?);
    }
    Ok(setup)
}

fn resolve_params(input: &Value, mode: Option<&str>) -> Map<String, Value> {
    let mut params = input.as_object().cloned().unwrap_or_default();
    if let Some(m) = mode {
        params.insert("bindingMode".into(), json!(m));
    }
    params.entry("statementLimit").or_insert(json!(500));
    params.entry("now").or_insert(json!(NOW));
    params
}

fn run_query(
    setup: &Setup,
    qtype: &str,
    input: &Value,
    mode: Option<&str>,
) -> Result<Value, String> {
    let limits = limits();
    let g = &setup.graph;
    match qtype {
        "trust" | "rating" => {
            let params = resolve_params(input, mode);
            let q = ResolveQuery::parse(&params, &limits, NOW)
                .map_err(|e| format!("invalid input: {e}"))?;
            let mut ctx = ExecCtx::new(0, &limits);
            ctx.own = &setup.own;
            let budget = |name: &str| {
                input
                    .get("budgets")
                    .and_then(|b| b.get(name))
                    .or_else(|| input.get(name))
                    .and_then(Value::as_u64)
            };
            let nodes = budget("maxReachedNodes");
            let records = budget("maxWalkRecords");
            if nodes.is_some() || records.is_some() {
                ctx.budgets = Some((
                    nodes.map_or(limits.max_reached_nodes, |n| n as usize),
                    records.map_or(limits.max_walk_records, |n| n as usize),
                ));
            }
            Ok(if qtype == "trust" {
                execute_trust(g, &q, &ctx)
            } else {
                execute_rating(g, &q, &ctx)
            })
        }
        "lookup-incoming" | "lookup-outgoing" => {
            let mut params = input.as_object().cloned().unwrap_or_default();
            params
                .entry("limit")
                .or_insert(json!(limits.max_lookup_page));
            params.entry("now").or_insert(json!(NOW));
            let p = LookupParams::parse(&params, &limits, NOW)
                .map_err(|e| format!("invalid input: {e}"))?;
            let dir = if qtype == "lookup-incoming" {
                Direction::Incoming
            } else {
                Direction::Outgoing
            };
            lookup_page(g, &p, dir, 0, &limits).map_err(|e| e.to_string())
        }
        "lookup-counts" => {
            let mut params = input.as_object().cloned().unwrap_or_default();
            params.entry("now").or_insert(json!(NOW));
            lookup_counts(g, &params, 0, &limits, NOW).map_err(|e| e.to_string())
        }
        "neighborhood" => {
            let mut params = input.as_object().cloned().unwrap_or_default();
            params.entry("now").or_insert(json!(NOW));
            neighborhood(g, &params, 0, &limits, NOW).map_err(|e| e.to_string())
        }
        "frontier" => {
            let mut params = input.as_object().cloned().unwrap_or_default();
            params.entry("now").or_insert(json!(NOW));
            dtp_resolve::frontier::frontier(g, &params, 0, NOW).map_err(|e| e.to_string())
        }
        "field" => {
            let mut params = input.as_object().cloned().unwrap_or_default();
            if let Some(m) = mode {
                params.insert("bindingMode".into(), json!(m));
            }
            params.entry("now").or_insert(json!(NOW));
            dtp_resolve::frontier::field(g, &params, 0, &limits, NOW).map_err(|e| e.to_string())
        }
        other => Err(format!("unsupported query type {other}")),
    }
}

fn run_pages(
    setup: &Setup,
    qtype: &str,
    input: &Value,
    pages: &[Value],
    errors: &mut Vec<String>,
    qi: usize,
) {
    let limits = limits();
    let dir = if qtype == "lookup-incoming" {
        Direction::Incoming
    } else {
        Direction::Outgoing
    };
    let mut cursor: Option<String> = None;
    for (pi, page) in pages.iter().enumerate() {
        let mut params = input.as_object().cloned().unwrap_or_default();
        params.entry("now").or_insert(json!(NOW));
        if let Some(limit) = page.get("limit") {
            params.insert("limit".into(), limit.clone());
        }
        if let Some(c) = &cursor {
            params.insert("cursor".into(), json!(c));
        }
        let result = LookupParams::parse(&params, &limits, NOW)
            .and_then(|p| lookup_page(&setup.graph, &p, dir, 0, &limits));
        let result = match result {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("query[{qi}] page[{pi}]: {e}"));
                return;
            }
        };
        let items = result["items"].as_array().cloned().unwrap_or_default();
        if let Some(expect) = page.get("expectItems").and_then(Value::as_array) {
            let expected: Vec<Value> = expect
                .iter()
                .map(|e| match e {
                    Value::String(id) => json!({ "eventId": id }),
                    other => other.clone(),
                })
                .collect();
            compare(
                &Value::Array(expected),
                Some(&Value::Array(items)),
                &format!("query[{qi}].page[{pi}].items"),
                errors,
            );
        }
        let next = result
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(want) = page.get("expectNextCursor").and_then(Value::as_bool)
            && want != next.is_some()
        {
            errors.push(format!(
                "query[{qi}] page[{pi}]: nextCursor present = {} (expected {want})",
                next.is_some()
            ));
        }
        cursor = next;
    }
}

fn is_bind_expect(expect: &Value) -> bool {
    expect.get("lenient").is_some() || expect.get("strict").is_some()
}

/// Canonical results of every query of a case (for the properties).
fn all_results(setup: &Setup, queries: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for q in queries {
        let qtype = q.get("type").and_then(Value::as_str).unwrap_or("");
        let input = q.get("input").cloned().unwrap_or(Value::Null);
        for mode in [Some("lenient"), Some("strict")] {
            let m = if matches!(qtype, "trust" | "rating" | "field") {
                mode
            } else {
                None
            };
            let r = run_query(setup, qtype, &input, m);
            out.push(match r {
                Ok(v) => canonicalize(&v).to_string(),
                Err(e) => e,
            });
            if m.is_none() {
                break;
            }
        }
    }
    out
}

fn check_properties(case: &Value, base: &Setup, queries: &[Value], errors: &mut Vec<String>) {
    let reference = all_results(base, queries);
    if case.get("ops").and_then(Value::as_array).is_none() {
        for (name, order) in [
            ("order independence (reversed)", Order::Reversed),
            ("order independence (shuffled)", Order::Shuffled(7)),
            ("order independence (shuffled)", Order::Shuffled(1234)),
            ("idempotence", Order::Doubled),
        ] {
            match build(case, order) {
                Ok(setup) => {
                    let other = all_results(&setup, queries);
                    if let Some((i, (a, b))) = reference
                        .iter()
                        .zip(&other)
                        .enumerate()
                        .find(|(_, (a, b))| a != b)
                    {
                        let at = a
                            .chars()
                            .zip(b.chars())
                            .position(|(x, y)| x != y)
                            .unwrap_or(0);
                        let window = |s: &str| {
                            s.chars()
                                .skip(at.saturating_sub(40))
                                .take(120)
                                .collect::<String>()
                        };
                        errors.push(format!(
                            "property {name} violated at result {i}: …{}… vs …{}…",
                            window(a),
                            window(b)
                        ));
                    }
                }
                Err(e) => errors.push(format!("property {name}: {e}")),
            }
        }
    }
    let limits = limits();
    for (qi, q) in queries.iter().enumerate() {
        let qtype = q.get("type").and_then(Value::as_str).unwrap_or("");
        let input = q.get("input").cloned().unwrap_or(Value::Null);
        match qtype {
            "trust" | "rating" => {
                for mode in ["lenient", "strict"] {
                    let Ok(single) = run_query(base, qtype, &input, Some(mode)) else {
                        continue;
                    };
                    // Strict needs a claim.
                    if mode == "strict"
                        && single
                            .get("binding")
                            .and_then(|b| b.get("pubkey"))
                            .is_some()
                        && single["binding"]["confirmed"] != json!(true)
                    {
                        errors.push(format!("query[{qi}]: strict bind without a claim"));
                    }
                    // Batch = single.
                    if input.get("maxReachedNodes").is_some()
                        || input.get("maxWalkRecords").is_some()
                        || input.get("budgets").is_some()
                    {
                        continue;
                    }
                    // Field = walk (resolver-engine.md § Root field).
                    let params = resolve_params(&input, Some(mode));
                    if let Ok(rq) = ResolveQuery::parse(&params, &limits, NOW) {
                        let kind = if qtype == "trust" {
                            KIND_TRUST
                        } else {
                            KIND_RATING
                        };
                        let mut fctx = ExecCtx::new(0, &limits);
                        fctx.own = &base.own;
                        let threshold = dtp_resolve::results::threshold_for(kind, &rq);
                        if let Some(p) = dtp_resolve::results::walk_params(
                            &base.graph,
                            &rq,
                            &fctx,
                            kind,
                            threshold,
                        ) {
                            let mut field =
                                dtp_resolve::field::Field::build(&base.graph, p, &rq.hop_context);
                            if !rq.format_path
                                && field.serves(kind, &rq.context)
                                && field.truncated().is_none()
                            {
                                let via_field = dtp_resolve::results::from_field(
                                    &base.graph,
                                    &rq,
                                    &fctx,
                                    kind,
                                    &mut field,
                                );
                                if canonicalize(&via_field) != canonicalize(&single) {
                                    errors.push(format!("query[{qi}]: field != walk ({mode})"));
                                }
                            }
                        }
                    }
                    let mut shared = resolve_params(&input, Some(mode));
                    let mut item = Map::new();
                    item.insert("key".into(), json!("k"));
                    for f in ["subject", "context", "labels"] {
                        if let Some(v) = shared.remove(f) {
                            item.insert(f.into(), v);
                        }
                    }
                    let mut ctx = ExecCtx::new(0, &limits);
                    ctx.own = &base.own;
                    let kind = if qtype == "trust" {
                        KIND_TRUST
                    } else {
                        KIND_RATING
                    };
                    match execute_batch(
                        &base.graph,
                        &shared,
                        &[Value::Object(item)],
                        kind,
                        &ctx,
                        NOW,
                        None,
                    ) {
                        Ok(batch) => {
                            if canonicalize(&batch["results"]["k"]) != canonicalize(&single) {
                                errors.push(format!("query[{qi}]: batch != single ({mode})"));
                            }
                        }
                        Err(e) => errors.push(format!("query[{qi}]: batch failed: {e}")),
                    }
                }
            }
            "lookup-incoming" | "lookup-outgoing" => {
                let dir = if qtype == "lookup-incoming" {
                    Direction::Incoming
                } else {
                    Direction::Outgoing
                };
                let Ok(full) = run_query(base, qtype, &input, None) else {
                    continue;
                };
                let full_items = full["items"].as_array().cloned().unwrap_or_default();
                // Pages add up.
                let mut paged = Vec::new();
                let mut cursor: Option<String> = None;
                for _ in 0..=full_items.len() {
                    let mut params = input.as_object().cloned().unwrap_or_default();
                    params.insert("limit".into(), json!(1));
                    params.insert("withTotals".into(), json!(true));
                    params.entry("now").or_insert(json!(NOW));
                    if let Some(c) = &cursor {
                        params.insert("cursor".into(), json!(c));
                    }
                    let Ok(p) = LookupParams::parse(&params, &limits, NOW) else {
                        break;
                    };
                    let Ok(page) = lookup_page(&base.graph, &p, dir, 0, &limits) else {
                        break;
                    };
                    paged.extend(page["items"].as_array().cloned().unwrap_or_default());
                    match page.get("nextCursor").and_then(Value::as_str) {
                        Some(c) => cursor = Some(c.to_string()),
                        None => break,
                    }
                }
                if paged != full_items {
                    errors.push(format!("query[{qi}]: pages do not add up"));
                }
                // Counts = items.
                let mut tally = [0u64; 4];
                for item in &full_items {
                    match (item.get("value").and_then(Value::as_i64), item.get("score")) {
                        (Some(1), _) => tally[0] += 1,
                        (Some(0), _) => tally[1] += 1,
                        (Some(-1), _) => tally[2] += 1,
                        (_, Some(_)) => tally[3] += 1,
                        _ => {}
                    }
                }
                let mut params = input.as_object().cloned().unwrap_or_default();
                params.insert(
                    "direction".into(),
                    json!(if dir == Direction::Incoming {
                        "incoming"
                    } else {
                        "outgoing"
                    }),
                );
                params.entry("now").or_insert(json!(NOW));
                params.remove("limit");
                params.remove("cursor");
                if let Ok(counts) = lookup_counts(&base.graph, &params, 0, &limits, NOW) {
                    let keys = input
                        .get("keys")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let merged = input.get("mergeKeys").and_then(Value::as_bool) == Some(true)
                        && dir == Direction::Incoming;
                    let slot = if merged {
                        Some(counts["counts"]["merged"].clone())
                    } else if keys.len() == 1 {
                        keys[0].as_str().map(|k| counts["counts"][k].clone())
                    } else {
                        None
                    };
                    if let Some(c) = slot {
                        let got = [&c["trust"], &c["neutral"], &c["distrust"], &c["ratings"]]
                            .map(|v| v.as_u64().unwrap_or(0));
                        if got != tally {
                            errors.push(format!("query[{qi}]: counts {got:?} != items {tally:?}"));
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Runs one model case (placeholders already expanded).
pub fn run_model_case(case: &Value) -> CaseOutcome {
    let tags: Vec<&str> = case
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let setup = match build(case, Order::Natural) {
        Ok(s) => s,
        Err(e) => return CaseOutcome::Fail(vec![format!("setup: {e}")]),
    };
    let queries: Vec<Value> = case
        .get("queries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let gap = tags.iter().any(|t| t.starts_with("gap:"));
    let mut errors = Vec::new();
    for (qi, q) in queries.iter().enumerate() {
        let qtype = q.get("type").and_then(Value::as_str).unwrap_or("");
        let input = q.get("input").cloned().unwrap_or(Value::Null);
        if let Some(pages) = q.get("pages").and_then(Value::as_array) {
            run_pages(&setup, qtype, &input, pages, &mut errors, qi);
            continue;
        }
        let expect = if gap {
            q.get("expectModel").or_else(|| q.get("expect"))
        } else {
            q.get("expect")
        };
        let Some(expect) = expect else { continue };
        let modes: Vec<&str> = q
            .get("modes")
            .and_then(Value::as_array)
            .map(|m| m.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let runs: Vec<(Option<&str>, &Value)> = if is_bind_expect(expect) {
            ["lenient", "strict"]
                .iter()
                .filter_map(|m| expect.get(*m).map(|e| (Some(*m), e)))
                .collect()
        } else if !modes.is_empty() {
            modes.iter().map(|m| (Some(*m), expect)).collect()
        } else {
            vec![(None, expect)]
        };
        for (mode, exp) in runs {
            match run_query(&setup, qtype, &input, mode) {
                Ok(actual) => {
                    let label = format!(
                        "query[{qi}]{}",
                        mode.map(|m| format!("({m})")).unwrap_or_default()
                    );
                    compare(
                        &canonicalize(exp),
                        Some(&canonicalize(&actual)),
                        &label,
                        &mut errors,
                    );
                }
                Err(e) => errors.push(format!("query[{qi}]: {e}")),
            }
        }
    }
    check_properties(case, &setup, &queries, &mut errors);
    if errors.is_empty() {
        CaseOutcome::Pass
    } else {
        CaseOutcome::Fail(errors)
    }
}
