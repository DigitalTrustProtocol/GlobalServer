//! Bytes per edge and walk / field timings on a seeded random graph.
//!
//! `cargo run --release -p dtp-resolve --example measure -- [nodes] [edges]`

use std::time::Instant;

use serde_json::json;

use dtp_graph::Graph;
use dtp_model::{EdgeRecord, KIND_TRUST, RecordValue, SubjectType, sha256_hex};
use dtp_resolve::field::Field;
use dtp_resolve::results::{from_field, threshold_for, walk_params};
use dtp_resolve::{ExecCtx, Limits, ResolveQuery, execute_trust};

fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let nodes = args.first().copied().unwrap_or(20_000);
    let edges = args.get(1).copied().unwrap_or(200_000);
    let keys: Vec<String> = (0..nodes).map(|i| sha256_hex(&format!("n{i}"))).collect();
    let mut state: u64 = 42;
    let mut rnd = |n: usize| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((state >> 33) as usize) % n
    };
    let mut g = Graph::new();
    let start = Instant::now();
    for i in 0..edges {
        let a = rnd(nodes);
        let b = rnd(nodes);
        let record = EdgeRecord {
            id: sha256_hex(&format!("e{i}")),
            pubkey: keys[a].clone(),
            kind: KIND_TRUST,
            created_at: 1_000 + i as u64,
            d: format!("{a}-{b}"),
            subject_type: SubjectType::P,
            subject: keys[b].clone(),
            context: "identity".into(),
            value: Some(RecordValue::Trust([1, 1, 1, 1, -1, 0][rnd(6)])),
            activate: None,
            expire: None,
            scope_rank: 2,
            hint_pubkey: None,
            content: String::new(),
            labels: vec![],
            label_hints: vec![],
        };
        g.apply_record(&record);
    }
    let ingest = start.elapsed();
    let start = Instant::now();
    g.compact();
    let compact = start.elapsed();
    let s = g.stats();
    let n_edges = s.trust_edges as f64;
    println!("nodes {} edges {}", s.nodes, s.trust_edges);
    println!(
        "ingest {:?} ({:.0} edges/s), compact {:?}",
        ingest,
        n_edges / ingest.as_secs_f64(),
        compact
    );
    println!(
        "hot {:.1} B/edge, cold {:.1} B/edge, core {:.1} B/node",
        s.hot_bytes as f64 / n_edges,
        s.cold_bytes as f64 / n_edges,
        s.core_bytes as f64 / s.nodes as f64
    );

    let mut limits = Limits::protocol_defaults();
    limits.operation_deadline_ms = 0;
    let ctx = ExecCtx::new(1, &limits);
    let base = json!({ "rootPubkey": keys[0], "subject": { "type": "p", "value": keys[1] }, "context": "identity", "now": 10_000, "followTrustThreshold": 50 });
    let q = ResolveQuery::parse(base.as_object().unwrap(), &limits, 0).unwrap();
    let start = Instant::now();
    let samples = 200;
    for i in 0..samples {
        let mut p = base.clone();
        p["subject"]["value"] = json!(keys[(i * 97) % nodes]);
        let q = ResolveQuery::parse(p.as_object().unwrap(), &limits, 0).unwrap();
        std::hint::black_box(execute_trust(&g, &q, &ctx));
    }
    println!(
        "exact walk: {:?} per query ({samples} queries)",
        start.elapsed() / samples as u32
    );
    let start = Instant::now();
    let params = walk_params(&g, &q, &ctx, KIND_TRUST, threshold_for(KIND_TRUST, &q)).unwrap();
    let mut field = Field::build(&g, params, "identity");
    let build = start.elapsed();
    let start = Instant::now();
    for i in 0..samples {
        let mut p = base.clone();
        p["subject"]["value"] = json!(keys[(i * 97) % nodes]);
        let q = ResolveQuery::parse(p.as_object().unwrap(), &limits, 0).unwrap();
        std::hint::black_box(from_field(&g, &q, &ctx, KIND_TRUST, &mut field));
    }
    println!(
        "root field: build {:?}, then {:?} per subject ({samples} subjects)",
        build,
        start.elapsed() / samples as u32
    );
}
