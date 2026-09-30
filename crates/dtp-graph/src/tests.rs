use dtp_model::{
    ClaimRecord, Deletion, DeletionTarget, EdgeRecord, KIND_RATING, KIND_TRUST, RecordValue,
    ScoreMicro, SubjectType, sha256_hex,
};

use super::*;

fn hex(name: &str) -> String {
    sha256_hex(name)
}

#[allow(clippy::too_many_arguments)]
fn rec(
    id: &str,
    author: &str,
    ty: SubjectType,
    subject: &str,
    context: &str,
    value: Option<i8>,
    created_at: u64,
    d: &str,
) -> EdgeRecord {
    EdgeRecord {
        id: hex(id),
        pubkey: hex(author),
        kind: KIND_TRUST,
        created_at,
        d: d.into(),
        subject_type: ty,
        subject: subject.into(),
        context: context.into(),
        value: value.map(RecordValue::Trust),
        activate: None,
        expire: None,
        scope_rank: 1,
        hint_pubkey: None,
        content: String::new(),
        labels: vec![],
        label_hints: vec![],
    }
}

fn trust(id: &str, author: &str, subject: &str, value: Option<i8>, at: u64) -> EdgeRecord {
    rec(
        id,
        author,
        SubjectType::P,
        &hex(subject),
        "",
        value,
        at,
        &format!("d-{author}-{subject}"),
    )
}

fn in_authors(g: &Graph, subject: &str) -> Vec<(NodeId, i8)> {
    let Some(node) = g.node_id(&hex(subject)) else {
        return vec![];
    };
    let mut out = Vec::new();
    for b in g.buckets(Adj::TrustIn, node) {
        out.extend(
            g.bucket(Adj::TrustIn, node, b)
                .map(|(e, _)| (e.node(), e.trust_value())),
        );
    }
    out.sort();
    out
}

#[test]
fn slot_winner_rules() {
    let mut g = Graph::new();
    assert_eq!(
        g.apply_record(&trust("e1", "a", "b", Some(1), 100)),
        ApplyOutcome::Accepted { replaced: false }
    );
    assert_eq!(
        g.apply_record(&trust("e1", "a", "b", Some(1), 100)),
        ApplyOutcome::Duplicate
    );
    assert_eq!(
        g.apply_record(&trust("e0", "a", "b", Some(-1), 99)),
        ApplyOutcome::Older
    );
    let a = g.node_id(&hex("a")).unwrap();
    assert_eq!(in_authors(&g, "b"), vec![(a, 1)]);

    // Newer replaces; equal created_at: lower id wins.
    assert_eq!(
        g.apply_record(&trust("e2", "a", "b", Some(-1), 101)),
        ApplyOutcome::Accepted { replaced: true }
    );
    assert_eq!(in_authors(&g, "b"), vec![(a, -1)]);
    let (lo, hi) = if hex("x1") < hex("x2") {
        ("x1", "x2")
    } else {
        ("x2", "x1")
    };
    assert_eq!(
        g.apply_record(&trust(hi, "a", "b", Some(0), 200)),
        ApplyOutcome::Accepted { replaced: true }
    );
    assert_eq!(
        g.apply_record(&trust(lo, "a", "b", Some(1), 200)),
        ApplyOutcome::Accepted { replaced: true }
    );
    assert_eq!(
        g.apply_record(&trust(hi, "a", "b", Some(0), 200)),
        ApplyOutcome::Older
    );
    assert_eq!(in_authors(&g, "b"), vec![(a, 1)]);

    // A Delete winner keeps older events out and contributes no edge.
    assert_eq!(
        g.apply_record(&trust("del", "a", "b", None, 300)),
        ApplyOutcome::Accepted { replaced: true }
    );
    assert_eq!(in_authors(&g, "b"), vec![]);
    assert_eq!(
        g.apply_record(&trust("old", "a", "b", Some(1), 250)),
        ApplyOutcome::Older
    );
    assert_eq!(g.stats().trust_edges, 0);
}

#[test]
fn delete_affects_its_own_slot_only() {
    // G3 fixed by construction: a Delete in one slot leaves a sibling slot
    // (same author, subject, bucket; different scope) untouched.
    let mut g = Graph::new();
    let b = hex("b");
    g.apply_record(&rec(
        "s1",
        "a",
        SubjectType::P,
        &b,
        "",
        Some(1),
        100,
        "slot-empty-scope",
    ));
    g.apply_record(&rec(
        "s2",
        "a",
        SubjectType::P,
        &b,
        "",
        Some(1),
        100,
        "slot-x-scope",
    ));
    let node = g.node_id(&b).unwrap();
    let bucket = g.contexts().get(KIND_TRUST, "").unwrap();
    let entries: Vec<_> = g.bucket(Adj::TrustIn, node, bucket).collect();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|(e, _)| e.has_siblings()));
    g.apply_record(&rec(
        "s3",
        "a",
        SubjectType::P,
        &b,
        "",
        None,
        200,
        "slot-empty-scope",
    ));
    let entries: Vec<_> = g.bucket(Adj::TrustIn, node, bucket).collect();
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].0.has_siblings());
    assert_eq!(g.edge(entries[0].1).id_hex(), hex("s2"));
}

#[test]
fn nip09_floors_and_tombstones() {
    let mut g = Graph::new();
    g.apply_record(&trust("e1", "a", "b", Some(1), 100));
    let del = Deletion {
        id: hex("k5"),
        pubkey: hex("a"),
        created_at: 150,
        targets: vec![DeletionTarget::Event(hex("e1"))],
        kinds: vec![],
    };
    let out = g.apply_deletion(&del);
    assert_eq!(out.removed, 1);
    assert_eq!(in_authors(&g, "b"), vec![]);
    // Re-push of the deleted event and anything at or below the floor is refused.
    assert_eq!(
        g.apply_record(&trust("e1", "a", "b", Some(1), 100)),
        ApplyOutcome::Deleted
    );
    assert_eq!(
        g.apply_record(&trust("e0", "a", "b", Some(1), 90)),
        ApplyOutcome::Deleted
    );
    // A later record above the floor is accepted normally.
    assert_eq!(
        g.apply_record(&trust("e2", "a", "b", Some(1), 101)),
        ApplyOutcome::Accepted { replaced: false }
    );

    // Another author cannot delete.
    let foreign = Deletion {
        pubkey: hex("mallory"),
        targets: vec![DeletionTarget::Event(hex("e2"))],
        ..del.clone()
    };
    assert_eq!(g.apply_deletion(&foreign).removed, 0);
    assert_eq!(in_authors(&g, "b").len(), 1);

    // Address deletion clears the slot up to its created_at and sets the floor.
    let addr = Deletion {
        id: hex("k5b"),
        pubkey: hex("a"),
        created_at: 500,
        targets: vec![DeletionTarget::Address {
            kind: KIND_TRUST,
            pubkey: hex("a"),
            d: "d-a-b".into(),
        }],
        kinds: vec![],
    };
    assert_eq!(g.apply_deletion(&addr).removed, 1);
    assert_eq!(
        g.apply_record(&trust("e3", "a", "b", Some(1), 499)),
        ApplyOutcome::Deleted
    );
    assert_eq!(
        g.apply_record(&trust("e4", "a", "b", Some(1), 501)),
        ApplyOutcome::Accepted { replaced: false }
    );

    // Deleting an unseen event by id blocks it when it arrives from its author.
    let early = Deletion {
        id: hex("k5c"),
        pubkey: hex("c"),
        created_at: 10,
        targets: vec![DeletionTarget::Event(hex("late"))],
        kinds: vec![],
    };
    assert_eq!(g.apply_deletion(&early).tombstones, 1);
    assert_eq!(
        g.apply_record(&trust("late", "c", "b", Some(1), 5)),
        ApplyOutcome::Deleted
    );
    assert_eq!(
        g.apply_record(&trust("later", "c", "b", Some(1), 6)),
        ApplyOutcome::Accepted { replaced: false }
    );
}

#[test]
fn witness_and_claim_indexes() {
    let mut g = Graph::new();
    let mut r = rec(
        "w1",
        "carol",
        SubjectType::I,
        "user:id:42",
        "identity",
        Some(1),
        100,
        "dw",
    );
    r.scope_rank = 2;
    r.hint_pubkey = Some(hex("p1"));
    g.apply_record(&r);
    let x = g.node_id("user:id:42").unwrap();
    let p1 = g.node_id(&hex("p1")).unwrap();
    assert_eq!(g.witness_edges(x).len(), 1);
    assert_eq!(g.hinted_as(p1).collect::<Vec<_>>(), vec![x]);
    // Person statement about a bindable account has a trust_out entry.
    let carol = g.node_id(&hex("carol")).unwrap();
    let b = g.contexts().get(KIND_TRUST, "identity").unwrap();
    assert_eq!(g.bucket(Adj::TrustOut, carol, b).count(), 1);

    // Distrust with a hint is not a witness.
    let mut r2 = r.clone();
    r2.id = hex("w2");
    r2.created_at = 200;
    r2.value = Some(RecordValue::Trust(-1));
    g.apply_record(&r2);
    assert_eq!(g.witness_edges(x).len(), 0);
    assert_eq!(g.hinted_as(p1).count(), 0);

    let claim = ClaimRecord {
        id: hex("c1"),
        pubkey: hex("p1"),
        created_at: 10,
        twitter_id: Some("42".into()),
    };
    assert_eq!(
        g.apply_claim(&claim),
        ApplyOutcome::Accepted { replaced: false }
    );
    assert!(g.claim(p1, "42").is_some());
    assert_eq!(g.claims_for("42").len(), 1);
    let revoke = ClaimRecord {
        id: hex("c2"),
        created_at: 11,
        twitter_id: None,
        ..claim.clone()
    };
    assert_eq!(
        g.apply_claim(&revoke),
        ApplyOutcome::Accepted { replaced: true }
    );
    assert!(g.claim(p1, "42").is_none());
    assert!(g.claims_for("42").is_empty());
    assert_eq!(g.apply_claim(&claim), ApplyOutcome::Older);
}

#[test]
fn ratings_and_other_out() {
    let mut g = Graph::new();
    let mut r = rec("r1", "a", SubjectType::I, "post:id:9", "", None, 100, "dr");
    r.kind = KIND_RATING;
    r.value = Some(RecordValue::Score(ScoreMicro(50_000_000)));
    r.scope_rank = 2;
    g.apply_record(&r);
    let a = g.node_id(&hex("a")).unwrap();
    let post = g.node_id("post:id:9").unwrap();
    assert_eq!(g.other_out(a).len(), 1);
    let bucket = g.contexts().get(KIND_RATING, "").unwrap();
    assert_eq!(g.bucket(Adj::RatingIn, post, bucket).count(), 1);
    assert_eq!(g.buckets(Adj::TrustOut, a), Vec::<BucketId>::new());
    assert_eq!(g.stats().rating_edges, 1);
}

#[test]
fn compaction_preserves_reads_and_dead_bits_hide_base_edges() {
    let mut g = Graph::new();
    for i in 0..50u64 {
        g.apply_record(&trust(
            &format!("e{i}"),
            &format!("a{}", i % 7),
            &format!("s{}", i % 5),
            Some(1),
            100 + i,
        ));
    }
    let before: Vec<_> = (0..5).map(|s| in_authors(&g, &format!("s{s}"))).collect();
    let snapshot = g.clone();
    g.compact();
    assert_eq!(g.delta_entries(), 0);
    let after: Vec<_> = (0..5).map(|s| in_authors(&g, &format!("s{s}"))).collect();
    assert_eq!(before, after);
    // The pre-compaction snapshot is unaffected (persistent values).
    let snap: Vec<_> = (0..5)
        .map(|s| in_authors(&snapshot, &format!("s{s}")))
        .collect();
    assert_eq!(snap, before);

    // Replace a base edge: dead bit hides it, delta holds the new winner.
    g.apply_record(&trust("n1", "a0", "s0", Some(-1), 1_000));
    let a0 = g.node_id(&hex("a0")).unwrap();
    let s0 = in_authors(&g, "s0");
    assert!(s0.contains(&(a0, -1)));
    assert!(!s0.contains(&(a0, 1)));
    assert_eq!(g.stats().dead_edges, 1);
    g.compact();
    assert_eq!(in_authors(&g, "s0"), s0);
    assert_eq!(g.stats().dead_edges, 0);
}
