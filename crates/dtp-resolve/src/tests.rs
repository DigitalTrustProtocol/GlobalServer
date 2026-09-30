use serde_json::{Value, json};

use dtp_graph::Graph;
use dtp_model::{
    EdgeRecord, KIND_RATING, KIND_TRUST, RecordValue, ScoreMicro, SubjectType, sha256_hex,
};

use crate::lookup::{Direction, LookupParams, lookup_page};
use crate::query::{Limits, ResolveQuery};
use crate::results::{ExecCtx, execute_rating, execute_trust};

fn h(name: &str) -> String {
    sha256_hex(name)
}

struct G {
    g: Graph,
    n: u64,
}

impl G {
    fn new() -> G {
        G {
            g: Graph::new(),
            n: 0,
        }
    }

    fn push(&mut self, author: &str, subject: &str, context: &str, value: i8) {
        self.push_full(author, SubjectType::P, &h(subject), context, value, None, 1);
    }

    #[allow(clippy::too_many_arguments)]
    fn push_full(
        &mut self,
        author: &str,
        ty: SubjectType,
        subject: &str,
        context: &str,
        value: i8,
        hint: Option<&str>,
        scope_rank: u8,
    ) {
        self.n += 1;
        let r = EdgeRecord {
            id: h(&format!("event-{}", self.n)),
            pubkey: h(author),
            kind: KIND_TRUST,
            created_at: 1_000 + self.n,
            d: format!("{author}|{subject}|{context}|{scope_rank}"),
            subject_type: ty,
            subject: subject.into(),
            context: context.into(),
            value: Some(RecordValue::Trust(value)),
            activate: None,
            expire: None,
            scope_rank,
            hint_pubkey: hint.map(h),
            content: String::new(),
            labels: vec![],
            label_hints: vec![],
        };
        self.g.apply_record(&r);
    }

    fn rate(&mut self, author: &str, post: &str, score: u32, labels: &[&str]) {
        self.n += 1;
        let r = EdgeRecord {
            id: h(&format!("event-{}", self.n)),
            pubkey: h(author),
            kind: KIND_RATING,
            created_at: 1_000 + self.n,
            d: format!("r|{author}|{post}"),
            subject_type: SubjectType::I,
            subject: post.into(),
            context: String::new(),
            value: Some(RecordValue::Score(ScoreMicro(score * 1_000_000))),
            activate: None,
            expire: None,
            scope_rank: 2,
            hint_pubkey: None,
            content: String::new(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
            label_hints: vec![],
        };
        self.g.apply_record(&r);
    }
}

fn trust(g: &Graph, root: &str, subject: Value, extra: Value) -> Value {
    let mut params =
        json!({ "rootPubkey": h(root), "subject": subject, "context": "identity", "now": 5_000 });
    for (k, v) in extra.as_object().unwrap() {
        params[k] = v.clone();
    }
    let limits = Limits::protocol_defaults();
    let q = ResolveQuery::parse(params.as_object().unwrap(), &limits, 0).unwrap();
    let mut ctx = ExecCtx::new(1, &limits);
    ctx.deadline = None;
    execute_trust(g, &q, &ctx)
}

fn p(name: &str) -> Value {
    json!({ "type": "p", "value": h(name) })
}

fn x(id: &str) -> Value {
    json!({ "type": "i", "value": format!("user:id:{id}") })
}

#[test]
fn chain_and_nearest_degree() {
    let mut t = G::new();
    t.push("alice", "bob", "identity", 1);
    t.push("bob", "carol", "identity", 1);
    t.push("carol", "dave", "identity", -1);
    t.push("bob", "dave", "identity", 1);
    let r = trust(&t.g, "alice", p("carol"), json!({}));
    assert_eq!(r["degree"], 2);
    assert_eq!(r["connected"], true);
    assert_eq!(r["resolution"], "trusted");
    assert_eq!(r["statements"][0]["distance"], 1);
    assert_eq!(r["statements"][0]["contextMatch"], "exact");
    // Dave: Bob (level 1) trusts him at degree 2; Carol's farther distrust
    // (degree 3) never dilutes it.
    let r = trust(&t.g, "alice", p("dave"), json!({}));
    assert_eq!(r["degree"], 2);
    assert_eq!(r["trust"], 1);
    assert_eq!(r["distrust"], 0);
    // Direct statement.
    let r = trust(&t.g, "alice", p("bob"), json!({}));
    assert_eq!(r["degree"], 1);
    assert_eq!(r["direct"]["distance"], 0);
    // Unknown subject: disconnected, no statements.
    let r = trust(&t.g, "alice", p("nobody"), json!({}));
    assert_eq!(r["connected"], false);
    assert_eq!(r["resolution"], "none");
    assert_eq!(r["statements"], json!([]));
}

#[test]
fn threshold_blocks_hop() {
    let mut t = G::new();
    t.push("alice", "b", "identity", 1);
    t.push("alice", "c", "identity", 1);
    t.push("b", "d", "identity", 1);
    t.push("c", "d", "identity", -1);
    t.push("d", "e", "identity", 1);
    let r = trust(&t.g, "alice", p("e"), json!({}));
    assert_eq!(r["connected"], false);
    let r = trust(&t.g, "alice", p("e"), json!({ "followTrustThreshold": 50 }));
    assert_eq!(r["degree"], 3);
    // D itself: mixed at degree 2.
    let r = trust(&t.g, "alice", p("d"), json!({}));
    assert_eq!(r["degree"], 2);
    assert_eq!(r["resolution"], "mixed");
}

#[test]
fn neutral_only_degree_does_not_stop_and_disconnected_has_no_statements() {
    let mut t = G::new();
    t.push("alice", "b", "identity", 1);
    t.push("alice", "s", "identity", 0);
    let r = trust(&t.g, "alice", p("s"), json!({}));
    assert_eq!(r["connected"], false);
    assert_eq!(r["statements"], json!([]));
    assert!(r.get("neutral").is_none());
    t.push("b", "s", "identity", 1);
    let r = trust(&t.g, "alice", p("s"), json!({}));
    assert_eq!(r["degree"], 2);
}

#[test]
fn context_chain_fallback_and_match_labels() {
    let mut t = G::new();
    t.push("alice", "b", "", 1);
    let r = trust(&t.g, "alice", p("b"), json!({}));
    assert_eq!(r["degree"], 1);
    assert_eq!(r["statements"][0]["contextMatch"], "general");
    t.push("alice", "c", "security", 1);
    let r = trust(
        &t.g,
        "alice",
        p("c"),
        json!({ "context": "security:access" }),
    );
    assert_eq!(r["statements"][0]["contextMatch"], "parent");
}

#[test]
fn binds_lenient_and_strict() {
    let mut t = G::new();
    // Alice trusts Carol; Carol witnesses X → P1 (no claim).
    t.push("alice", "carol", "identity", 1);
    t.push_full(
        "carol",
        SubjectType::I,
        "user:id:42",
        "identity",
        1,
        Some("p1"),
        2,
    );
    t.push("p1", "zed", "identity", 1);
    // Lenient: X binds to P1; P1's statements become hops.
    let r = trust(&t.g, "alice", p("zed"), json!({}));
    assert_eq!(r["degree"], 3);
    let r = trust(&t.g, "alice", x("42"), json!({}));
    assert_eq!(r["degree"], 2);
    assert_eq!(r["binding"]["source"], "witness");
    assert_eq!(r["binding"]["pubkey"], h("p1"));
    assert_eq!(r["binding"]["confirmed"], false);
    assert_eq!(r["binding"]["witnessDegree"], 2);
    // Strict: P1 has no claim → cut.
    let r = trust(&t.g, "alice", p("zed"), json!({ "bindingMode": "strict" }));
    assert_eq!(r["connected"], false);
    let r = trust(&t.g, "alice", x("42"), json!({ "bindingMode": "strict" }));
    assert_eq!(r["binding"]["source"], "none");
    assert_eq!(r["binding"]["cutReason"], "no-claim");
    // A claim confirms it.
    t.g.apply_claim_ids(&h("p1"), &h("claim"), 1, vec!["42".into()]);
    let r = trust(&t.g, "alice", p("zed"), json!({ "bindingMode": "strict" }));
    assert_eq!(r["degree"], 3);
    let r = trust(&t.g, "alice", x("42"), json!({ "bindingMode": "strict" }));
    assert_eq!(r["binding"]["confirmed"], true);
    assert_eq!(r["binding"]["claimEventId"], h("claim"));
}

#[test]
fn node_budget_truncates_deterministically() {
    let mut t = G::new();
    t.push("alice", "b", "identity", 1);
    t.push("b", "c", "identity", 1);
    t.push("c", "d", "identity", 1);
    let limits = Limits::protocol_defaults();
    let params =
        json!({ "rootPubkey": h("alice"), "subject": p("d"), "context": "identity", "now": 5000 });
    let q = ResolveQuery::parse(params.as_object().unwrap(), &limits, 0).unwrap();
    let mut ctx = ExecCtx::new(1, &limits);
    ctx.budgets = Some((2, 1_000));
    let r = execute_trust(&t.g, &q, &ctx);
    assert_eq!(r["connected"], false);
    assert_eq!(r["truncated"], true);
    assert_eq!(r["truncatedReasons"], json!(["nodeBudget"]));
    assert_eq!(r["completeDepth"], 1);
    // A hit within completeDepth + 1 is still exact.
    let q = ResolveQuery::parse(
        json!({ "rootPubkey": h("alice"), "subject": p("c"), "context": "identity", "now": 5000 })
            .as_object()
            .unwrap(),
        &limits,
        0,
    )
    .unwrap();
    let r = execute_trust(&t.g, &q, &ctx);
    assert_eq!(r["degree"], 2);
    assert_eq!(r["truncated"], false);
}

#[test]
fn ratings_mean_labels_and_own() {
    let mut t = G::new();
    t.push("alice", "b", "identity", 1);
    t.push("alice", "c", "identity", 1);
    t.rate("b", "post:id:7", 80, &["accurate"]);
    t.rate("c", "post:id:7", 45, &[]);
    t.rate("alice", "post:id:8", 10, &[]);
    let limits = Limits::protocol_defaults();
    let ctx = ExecCtx::new(3, &limits);
    let parse = |v: Value| ResolveQuery::parse(v.as_object().unwrap(), &limits, 0).unwrap();
    let r = execute_rating(
        &t.g,
        &parse(
            json!({ "rootPubkey": h("alice"), "subject": { "type": "i", "value": "post:id:7" }, "now": 5000 }),
        ),
        &ctx,
    );
    assert_eq!(r["degree"], 2);
    assert_eq!(r["claimCount"], 2);
    assert_eq!(r["averageScore"].as_f64(), Some(62.5));
    assert_eq!(r["claims"][0]["distance"], 1);
    let r = execute_rating(
        &t.g,
        &parse(
            json!({ "rootPubkey": h("alice"), "subject": { "type": "i", "value": "post:id:7" }, "labels": ["accurate"], "now": 5000 }),
        ),
        &ctx,
    );
    assert_eq!(r["claimCount"], 1);
    assert_eq!(r["averageScore"], 80);
    let r = execute_rating(
        &t.g,
        &parse(
            json!({ "rootPubkey": h("alice"), "subject": { "type": "i", "value": "post:id:7" }, "labels": ["nope"], "now": 5000 }),
        ),
        &ctx,
    );
    assert_eq!(r["claimCount"], 0);
    assert_eq!(r["degree"], 0);
    assert_eq!(r["averageScore"], Value::Null);
    let r = execute_rating(
        &t.g,
        &parse(
            json!({ "rootPubkey": h("alice"), "subject": { "type": "i", "value": "post:id:8" }, "now": 5000 }),
        ),
        &ctx,
    );
    assert_eq!(r["degree"], 1);
    assert_eq!(r["own"]["score"], 10);
}

/// Seeded random graphs: the root field answers exactly like the walk.
#[test]
fn field_equals_walk_on_random_graphs() {
    use crate::field::Field;
    use crate::results::{from_field, threshold_for, walk_params};
    let mut state: u64 = 0x5eed;
    let mut rnd = |n: u64| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) % n
    };
    let limits = Limits::protocol_defaults();
    let mut compared = 0;
    for seed in 0..12 {
        let mut t = G::new();
        let people: Vec<String> = (0..25).map(|i| format!("s{seed}-p{i}")).collect();
        for _ in 0..90 {
            let a = &people[rnd(25) as usize];
            let value = [1, 1, 1, -1, 0][rnd(5) as usize];
            let context = ["identity", "", "identity:attest"][rnd(3) as usize];
            match rnd(4) {
                0 => {
                    let hint = (rnd(2) == 0).then(|| people[rnd(25) as usize].clone());
                    let x = format!("user:id:{}", rnd(6));
                    t.push_full(a, SubjectType::I, &x, context, value, hint.as_deref(), 2);
                }
                1 => t.rate(a, &format!("post:id:{}", rnd(4)), rnd(101) as u32, &[]),
                _ => t.push(a, &people[rnd(25) as usize], context, value),
            }
        }
        for _ in 0..6 {
            let p = h(&people[rnd(25) as usize]);
            t.g.apply_claim_ids(
                &p,
                &h(&format!("claim-{seed}-{}", rnd(1000))),
                1,
                vec![rnd(6).to_string().into()],
            );
        }
        let subjects: Vec<Value> = people
            .iter()
            .map(|p| json!({ "type": "p", "value": h(p) }))
            .chain((0..6).map(|i| json!({ "type": "i", "value": format!("user:id:{i}") })))
            .chain((0..4).map(|i| json!({ "type": "i", "value": format!("post:id:{i}") })))
            .collect();
        for root in people.iter().take(3) {
            for mode in ["lenient", "strict"] {
                for (kind, context) in [
                    (dtp_model::KIND_TRUST, "identity"),
                    (dtp_model::KIND_RATING, ""),
                ] {
                    let base = json!({ "rootPubkey": h(root), "subject": subjects[0], "context": context, "now": 5000, "bindingMode": mode });
                    let q0 = ResolveQuery::parse(base.as_object().unwrap(), &limits, 0).unwrap();
                    let ctx = ExecCtx::new(1, &limits);
                    let Some(p) = walk_params(&t.g, &q0, &ctx, kind, threshold_for(kind, &q0))
                    else {
                        continue;
                    };
                    let mut field = Field::build(&t.g, p, &q0.hop_context);
                    for s in &subjects {
                        let mut params = base.clone();
                        params["subject"] = s.clone();
                        let q =
                            ResolveQuery::parse(params.as_object().unwrap(), &limits, 0).unwrap();
                        let walk = if kind == dtp_model::KIND_TRUST {
                            execute_trust(&t.g, &q, &ctx)
                        } else {
                            execute_rating(&t.g, &q, &ctx)
                        };
                        let via_field = from_field(&t.g, &q, &ctx, kind, &mut field);
                        assert_eq!(
                            walk, via_field,
                            "seed {seed} root {root} {mode} kind {kind} subject {s}"
                        );
                        compared += 1;
                    }
                }
            }
        }
    }
    assert!(compared > 2000);
}

#[test]
fn lookup_pages_add_up() {
    let mut t = G::new();
    for i in 0..7 {
        t.push(
            &format!("a{i}"),
            "target",
            "identity",
            if i % 3 == 0 { -1 } else { 1 },
        );
    }
    let limits = Limits::protocol_defaults();
    let key = format!("p:{}", h("target"));
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut params = json!({ "keys": [key], "context": "identity", "limit": 3, "withTotals": true, "now": 5000 });
        if let Some(c) = &cursor {
            params["cursor"] = json!(c);
        }
        let lp = LookupParams::parse(params.as_object().unwrap(), &limits, 0).unwrap();
        let page = lookup_page(&t.g, &lp, Direction::Incoming, 1, &limits).unwrap();
        assert_eq!(page["totals"]["trust"], 4);
        assert_eq!(page["totals"]["distrust"], 3);
        all.extend(page["items"].as_array().unwrap().iter().cloned());
        match page.get("nextCursor") {
            Some(c) => cursor = Some(c.as_str().unwrap().to_string()),
            None => break,
        }
    }
    assert_eq!(all.len(), 7);
    let times: Vec<u64> = all
        .iter()
        .map(|i| i["createdAt"].as_u64().unwrap())
        .collect();
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(times, sorted);
}
