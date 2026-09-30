//! Sync frontier (wot-model §8) and `graph.field`.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value, json};

use dtp_graph::{Adj, EdgeId, Graph, NodeId, NodeType};
use dtp_model::KIND_TRUST;

use crate::query::{Limits, ParamError, invalid, opt_str, opt_u64, parse_context, parse_pubkey};
use crate::walk::{BindingMode, Budgets, WalkParams, Walker};

struct Discovered {
    depth: u8,
    support: u32,
}

/// Lenient frontier bind: nearest witness among discovered authors at
/// depth ≤ `k` (rank: depth, support count, newer, lower author pubkey).
fn frontier_bind(
    g: &Graph,
    x: NodeId,
    k: u8,
    found: &HashMap<NodeId, Discovered>,
    now: u64,
) -> Option<NodeId> {
    let mut best: Option<(
        (u8, std::cmp::Reverse<u32>, std::cmp::Reverse<u64>, String),
        NodeId,
    )> = None;
    let mut per_author: HashMap<NodeId, EdgeId> = HashMap::new();
    for &e in g.witness_edges(x) {
        let edge = g.edge(e);
        if !edge.is_active_at(now) {
            continue;
        }
        per_author
            .entry(edge.author)
            .and_modify(|cur| {
                let c = g.edge(*cur);
                if (edge.created_at, std::cmp::Reverse(edge.id))
                    > (c.created_at, std::cmp::Reverse(c.id))
                {
                    *cur = e;
                }
            })
            .or_insert(e);
    }
    for (author, e) in per_author {
        let Some(d) = found.get(&author).filter(|d| d.depth <= k) else {
            continue;
        };
        let edge = g.edge(e);
        let rank = (
            d.depth,
            std::cmp::Reverse(d.support),
            std::cmp::Reverse(edge.created_at),
            g.node(author).key.value(),
        );
        if best.as_ref().is_none_or(|(r, _)| rank < *r) {
            best = Some((rank, edge.hint.expect("witness has a hint")));
        }
    }
    best.map(|(_, p)| p)
}

/// `graph.frontier` (`GraphManager.positiveAuthorFrontier` with binds).
pub fn frontier(
    g: &Graph,
    params: &Map<String, Value>,
    graph_version: u64,
    server_now: u64,
) -> Result<Value, ParamError> {
    let Some(Value::Array(roots)) = params.get("roots") else {
        return invalid("roots must be an array of pubkeys");
    };
    let max_depth = opt_u64(params, "maxDepth")?.unwrap_or(4).min(7) as u8;
    let per_level = opt_u64(params, "maxAuthorsPerLevel")?.unwrap_or(250) as usize;
    let max_total = opt_u64(params, "maxTotalAuthors")?.unwrap_or(1_000) as usize;
    let now = opt_u64(params, "now")?.unwrap_or(server_now);
    let mut reasons: Vec<&str> = Vec::new();
    let add_reason = |reasons: &mut Vec<&str>, r: &'static str| {
        if !reasons.contains(&r) {
            reasons.push(r);
        }
    };
    let mut root_keys: Vec<String> = roots
        .iter()
        .filter_map(|r| r.as_str().map(|s| s.trim().to_ascii_lowercase()))
        .filter(|s| dtp_model::is_hex64(s))
        .collect();
    root_keys.sort();
    root_keys.dedup();
    if root_keys.len() > per_level {
        root_keys.truncate(per_level);
        add_reason(&mut reasons, "maxAuthorsPerLevel");
    }
    if root_keys.len() > max_total {
        root_keys.truncate(max_total);
        add_reason(&mut reasons, "maxTotalAuthors");
    }
    let mut order: Vec<(String, u8, Option<String>)> =
        root_keys.iter().map(|k| (k.clone(), 0, None)).collect();
    let mut found: HashMap<NodeId, Discovered> = HashMap::new();
    let mut found_keys: std::collections::HashSet<String> = root_keys.iter().cloned().collect();
    let mut current: Vec<NodeId> = Vec::new();
    for k in &root_keys {
        if let Some(n) = g.node_id(k) {
            found.insert(
                n,
                Discovered {
                    depth: 0,
                    support: 0,
                },
            );
            current.push(n);
        }
    }
    let hop_buckets = g.contexts().chain(KIND_TRUST, "identity");
    for depth in 0..=max_depth {
        // children: pubkey -> (node, lowest supporting author pubkey, support count)
        let mut children: BTreeMap<String, (NodeId, String, u32)> = BTreeMap::new();
        for &a in &current {
            let author_key = g.node(a).key.value();
            let mut seen_peer: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
            for &b in &hop_buckets {
                for (entry, e) in g.bucket(Adj::TrustOut, a, b) {
                    let edge = g.edge(e);
                    if edge.trust_value() != Some(1) || !edge.is_active_at(now) {
                        continue;
                    }
                    let target = entry.node();
                    let peer = if g.node(target).is_bindable() {
                        match frontier_bind(g, target, depth, &found, now) {
                            Some(p) => p,
                            None => continue,
                        }
                    } else {
                        target
                    };
                    if g.node(peer).ty != NodeType::P {
                        continue;
                    }
                    let key = g.node(peer).key.value();
                    if found_keys.contains(&key) {
                        continue;
                    }
                    let first_for_author = seen_peer.insert(peer);
                    children
                        .entry(key)
                        .and_modify(|(_, via, support)| {
                            if author_key < *via {
                                *via = author_key.clone();
                            }
                            if first_for_author {
                                *support += 1;
                            }
                        })
                        .or_insert((peer, author_key.clone(), 1));
                }
            }
        }
        if depth == max_depth {
            if !children.is_empty() {
                add_reason(&mut reasons, "maxDepth");
            }
            break;
        }
        let mut next: Vec<(String, (NodeId, String, u32))> = children.into_iter().collect();
        if next.len() > per_level {
            next.truncate(per_level);
            add_reason(&mut reasons, "maxAuthorsPerLevel");
        }
        let remaining = max_total.saturating_sub(found_keys.len());
        if next.len() > remaining {
            next.truncate(remaining);
            add_reason(&mut reasons, "maxTotalAuthors");
        }
        current = Vec::new();
        for (key, (node, via, support)) in next {
            found_keys.insert(key.clone());
            found.insert(
                node,
                Discovered {
                    depth: depth + 1,
                    support,
                },
            );
            order.push((key, depth + 1, Some(via)));
            current.push(node);
        }
        if current.is_empty() {
            break;
        }
    }
    let authors: Vec<Value> = order
        .into_iter()
        .map(|(pubkey, depth, via)| {
            let mut a = Map::new();
            a.insert("pubkey".into(), json!(pubkey));
            a.insert("depth".into(), json!(depth));
            if let Some(v) = via {
                a.insert("via".into(), json!(v));
            }
            Value::Object(a)
        })
        .collect();
    Ok(json!({ "graphVersion": graph_version, "authors": authors, "reasons": reasons }))
}

/// `graph.field`: qualifying nodes per level `Q[0..D−1]` and the binds
/// decided while building them (resolver-engine.md § Root field).
pub fn field(
    g: &Graph,
    params: &Map<String, Value>,
    graph_version: u64,
    limits: &Limits,
    server_now: u64,
) -> Result<Value, ParamError> {
    let root = match params.get("rootPubkey") {
        Some(v) if !v.is_null() => parse_pubkey(v, "rootPubkey")?,
        _ => return invalid("rootPubkey is required"),
    };
    let hop_context = parse_context(params, "hopContext", "identity")?;
    let threshold = params
        .get("threshold")
        .or_else(|| params.get("followTrustThreshold"))
        .and_then(Value::as_f64);
    let threshold = dtp_model::score::clamp_green(threshold);
    let max_depth = opt_u64(params, "maxDepth")?
        .or(params
            .get("bounds")
            .and_then(|b| b.get("maxDepth"))
            .and_then(Value::as_u64))
        .unwrap_or(4)
        .clamp(1, 7)
        .min(u64::from(limits.max_depth)) as u8;
    let mode = match opt_str(params, "bindingMode")? {
        None => BindingMode::Lenient,
        Some(m) => BindingMode::parse(m)
            .ok_or_else(|| ParamError("bindingMode must be lenient or strict".into()))?,
    };
    let now = opt_u64(params, "now")?.unwrap_or(server_now);
    let Some(root_node) = g.node_id(&root) else {
        return Ok(
            json!({ "graphVersion": graph_version, "completeDepth": max_depth - 1, "levels": [[root]], "binds": [] }),
        );
    };
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(limits.operation_deadline_ms);
    let params = WalkParams {
        root: root_node,
        subject: None,
        kind: KIND_TRUST,
        hop_buckets: g.contexts().chain(KIND_TRUST, &hop_context),
        score_buckets: Vec::new(),
        threshold,
        max_depth,
        now,
        mode,
        own: Vec::new(),
        budgets: Budgets {
            max_nodes: limits.max_reached_nodes,
            max_records: limits.max_walk_records,
            deadline: Some(deadline),
        },
        track_contrib: false,
    };
    let mut walker = Walker::new(g, params);
    let mut complete = 0u8;
    let mut reason = None;
    for level in 0..max_depth.saturating_sub(1) {
        match walker.expand(level, None) {
            Ok(nonempty) => {
                complete = level + 1;
                if !nonempty {
                    complete = max_depth - 1;
                    break;
                }
            }
            Err(r) => {
                reason = Some(r);
                break;
            }
        }
    }
    let mut levels: Vec<Value> = Vec::new();
    for (i, level) in walker.levels.iter().enumerate() {
        if i >= max_depth as usize {
            break;
        }
        let mut keys: Vec<String> = level
            .iter()
            .filter(|&&n| walker.qualifies(n))
            .map(|&n| g.node(n).key.value())
            .collect();
        keys.sort();
        levels.push(json!(keys));
    }
    let binds: Vec<Value> = walker
        .bound_list()
        .into_iter()
        .map(|(x, b)| {
            let mut o = Map::new();
            o.insert(
                "subject".into(),
                json!(format!("i:{}", g.node(x).key.value())),
            );
            o.insert("pubkey".into(), json!(g.node(b.pubkey).key.value()));
            o.insert("source".into(), json!(b.source.as_str()));
            if let Some(l) = b.witness_level {
                o.insert("level".into(), json!(l));
            }
            if let Some(w) = b.witness {
                o.insert("witnessEventId".into(), json!(g.edge(w).id_hex()));
            }
            Value::Object(o)
        })
        .collect();
    let mut out = Map::new();
    out.insert("graphVersion".into(), json!(graph_version));
    out.insert("completeDepth".into(), json!(complete));
    out.insert("levels".into(), Value::Array(levels));
    out.insert("binds".into(), Value::Array(binds));
    if let Some(r) = reason {
        out.insert("truncated".into(), json!(true));
        out.insert("truncatedReasons".into(), json!([r.as_str()]));
    }
    Ok(Value::Object(out))
}
