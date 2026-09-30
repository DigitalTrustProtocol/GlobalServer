//! Writes the signed protocol cases of `tests/cases/protocol/` (run once;
//! signatures use random auxiliary data, so regenerated files differ in
//! `sig` / `id` bytes only).
//!
//! `cargo run -p dtp-conformance --example gen_protocol_cases`

use std::path::PathBuf;

use serde_json::{Value, json};

use dtp_model::statement::StatementBuilder;
use dtp_model::{Event, KIND_DELETION, KIND_IDENTITY, Keys, Subject, SubjectType, encode_npub};

const T: u64 = 1_700_000_000;

fn case(id: &str, tags: &[&str], event: &Event, expect: Value) -> Value {
    json!({ "id": id, "kind": "protocol", "tags": tags, "profile": "x.com", "event": event.to_value(), "expect": expect })
}

fn resign(keys: &Keys, event: &Event, tags: Vec<Vec<String>>) -> Event {
    keys.sign_event(event.created_at, event.kind, tags, &event.content)
}

fn main() {
    let alice = Keys::from_seed("alice");
    let owner = Keys::from_seed("owner");
    let npub = encode_npub(owner.pubkey()).unwrap();
    let account = Subject::new(SubjectType::I, "user:id:11348282");
    let post = Subject::new(SubjectType::I, "post:id:2080659774136291424");
    let mut cases = Vec::new();

    let e = StatementBuilder::trust(account.clone(), "1")
        .scope("x.com")
        .context("identity")
        .hint("user:name:nasa")
        .hint(&npub)
        .sign(&alice, T);
    cases.push(case("protocol-trust-user-identity-hint", &["protocol", "nip-examples"], &e, json!({
        "valid": true, "eligible": true, "errors": [],
        "record": { "kind": 32009, "subjectType": "i", "subject": "user:id:11348282", "context": "identity",
                    "value": 1, "scopeRank": 2, "hintPubkey": owner.pubkey(), "pubkey": alice.pubkey(),
                    "dTag": dtp_model::sha256_hex("user:id:11348282:x.com:identity") }
    })));

    let e = StatementBuilder::trust(account.clone(), "1")
        .hint(&npub)
        .sign(&alice, T);
    cases.push(case(
        "protocol-empty-scope-rank1-no-hint",
        &["protocol", "scope"],
        &e,
        json!({
            "valid": true, "eligible": true, "record": { "scopeRank": 1, "context": "" }
        }),
    ));

    let e = StatementBuilder::trust(post.clone(), "-1")
        .scope("x.com")
        .sign(&alice, T);
    cases.push(case("protocol-distrust-post", &["protocol", "nip-examples"], &e, json!({
        "valid": true, "eligible": true, "record": { "value": -1, "subject": "post:id:2080659774136291424", "scopeRank": 2 }
    })));

    let e = StatementBuilder::trust(account.clone(), "1")
        .scope("x.com")
        .scope("twitter.com")
        .sign(&alice, T);
    cases.push(case("protocol-multi-scope-d", &["protocol", "nip-examples", "d"], &e, json!({
        "valid": true, "eligible": true,
        "record": { "dTag": dtp_model::sha256_hex("user:id:11348282:twitter.com,x.com:"), "scopeRank": 2 }
    })));

    let e = StatementBuilder::trust(
        Subject::new(SubjectType::P, Keys::from_seed("bob").pubkey()),
        "1",
    )
    .scope("nostr")
    .context("development")
    .sign(&alice, T);
    cases.push(case(
        "protocol-other-scope-ineligible",
        &["protocol", "scope"],
        &e,
        json!({ "valid": true, "eligible": false }),
    ));

    let e = StatementBuilder::trust(account.clone(), "0")
        .scope("x.com")
        .label("reviewer", Some("Trusted <i>reviewer</i>"))
        .content("watching")
        .sign(&alice, T);
    cases.push(case("protocol-neutral-label", &["protocol", "labels"], &e, json!({
        "valid": true, "eligible": true,
        "record": { "value": 0, "labels": ["reviewer"], "labelHints": { "reviewer": "Trusted ireviewer/i" }, "content": "watching" }
    })));

    let e = StatementBuilder::trust(account.clone(), "")
        .scope("x.com")
        .sign(&alice, T);
    cases.push(case(
        "protocol-delete-no-value",
        &["protocol", "delete"],
        &e,
        json!({ "valid": true, "eligible": true, "record": { "context": "" } }),
    ));

    let e = StatementBuilder::trust(
        Subject::new(SubjectType::P, Keys::from_seed("bob").pubkey()),
        "1",
    )
    .window(Some(10), Some(20))
    .sign(&alice, T);
    cases.push(case(
        "protocol-window",
        &["protocol", "window"],
        &e,
        json!({ "valid": true, "record": { "activate": 10, "expire": 20 } }),
    ));

    let e = StatementBuilder::rating(post.clone(), "87.5")
        .label("accurate", None)
        .sign(&alice, T);
    cases.push(case("protocol-rating", &["protocol", "rating"], &e, json!({
        "valid": true, "eligible": true, "record": { "kind": 32014, "value": 87.5, "labels": ["accurate"], "scopeRank": 2 }
    })));

    let mut r = StatementBuilder::rating(post.clone(), "50");
    r.scopes.clear();
    cases.push(case(
        "protocol-rating-needs-x-scope",
        &["protocol", "rating", "scope"],
        &r.sign(&alice, T),
        json!({ "valid": true, "eligible": false }),
    ));

    // Invalid events.
    let base = StatementBuilder::trust(account.clone(), "1")
        .scope("x.com")
        .sign(&alice, T);
    let mut t = base.tags.clone();
    t[0][1] = "00".repeat(32);
    cases.push(case(
        "protocol-d-mismatch",
        &["protocol", "d"],
        &resign(&alice, &base, t),
        json!({ "valid": false, "errors": ["d-mismatch"] }),
    ));

    let mut t = base.tags.clone();
    t.push(vec!["p".into(), Keys::from_seed("bob").pubkey().into()]);
    cases.push(case(
        "protocol-two-subjects",
        &["protocol", "subject"],
        &resign(&alice, &base, t),
        json!({ "valid": false, "errors": ["subject-tag"] }),
    ));

    let mut t = base.tags.clone();
    t[1].push("npub1invalid".into());
    cases.push(case(
        "protocol-malformed-npub-hint",
        &["protocol", "hint"],
        &resign(&alice, &base, t),
        json!({ "valid": false, "errors": ["hint"] }),
    ));

    let mut t = base.tags.clone();
    t[2][1] = "2".into();
    cases.push(case(
        "protocol-bad-v",
        &["protocol", "value"],
        &resign(&alice, &base, t),
        json!({ "valid": false, "errors": ["value"] }),
    ));

    let mut t = base.tags.clone();
    t.push(vec!["x".into(), "30".into()]);
    t.push(vec!["y".into(), "20".into()]);
    cases.push(case(
        "protocol-window-order",
        &["protocol", "window"],
        &resign(&alice, &base, t),
        json!({ "valid": false, "errors": ["window"] }),
    ));

    let mut t = base.tags.clone();
    t.push(vec!["c".into(), "Identity".into()]);
    cases.push(case(
        "protocol-context-not-canonical",
        &["protocol", "context"],
        &resign(&alice, &base, t),
        json!({ "valid": false, "errors": ["context"] }),
    ));

    let long = alice.sign_event(T, 32009, base.tags.clone(), &"x".repeat(1025));
    cases.push(case(
        "protocol-content-limit",
        &["protocol", "content"],
        &long,
        json!({ "valid": false, "errors": ["content-length"] }),
    ));

    let mut tampered = base.clone();
    tampered.content = "tampered".into();
    cases.push(case(
        "protocol-id-mismatch",
        &["protocol", "signature"],
        &tampered,
        json!({ "valid": false, "errors": ["id-mismatch"] }),
    ));

    let mut forged = base.clone();
    forged.sig = Keys::from_seed("mallory").sign_raw(&dtp_model::hex32(&base.id).unwrap());
    cases.push(case(
        "protocol-bad-signature",
        &["protocol", "signature"],
        &forged,
        json!({ "valid": false, "errors": ["bad-sig"] }),
    ));

    let mut r = StatementBuilder::rating(post.clone(), "12.50").tags();
    r[2][1] = "12.50".into();
    cases.push(case(
        "protocol-rating-score-not-canonical",
        &["protocol", "rating"],
        &alice.sign_event(T, 32014, r, ""),
        json!({ "valid": false, "errors": ["score"] }),
    ));

    let claim = owner.sign_event(
        T,
        KIND_IDENTITY,
        vec![
            vec!["i".into(), "twitter:nasa".into()],
            vec!["i".into(), "twitter_id:11348282".into()],
        ],
        "",
    );
    cases.push(case(
        "protocol-10011-claim",
        &["protocol", "claims"],
        &claim,
        json!({ "valid": true, "claim": { "pubkey": owner.pubkey(), "twitterId": "11348282" } }),
    ));

    let revoked = owner.sign_event(
        T + 1,
        KIND_IDENTITY,
        vec![vec!["i".into(), "github:owner".into(), "gist".into()]],
        "",
    );
    cases.push(case(
        "protocol-10011-no-claim",
        &["protocol", "claims"],
        &revoked,
        json!({ "valid": true, "claim": null }),
    ));

    let del = alice.sign_event(
        T,
        KIND_DELETION,
        vec![
            vec!["e".into(), base.id.clone()],
            vec!["k".into(), "32009".into()],
        ],
        "",
    );
    cases.push(case(
        "protocol-kind5-targets-32009",
        &["protocol", "nip09"],
        &del,
        json!({ "valid": true, "eligible": true }),
    ));

    let del = alice.sign_event(
        T,
        KIND_DELETION,
        vec![
            vec!["e".into(), base.id.clone()],
            vec!["k".into(), "1".into()],
        ],
        "",
    );
    cases.push(case(
        "protocol-kind5-other-kind",
        &["protocol", "nip09"],
        &del,
        json!({ "valid": true, "eligible": false }),
    ));

    let other = alice.sign_event(T, 1, vec![], "hello");
    cases.push(case(
        "protocol-kind1-blocked",
        &["protocol", "kind"],
        &other,
        json!({ "valid": true, "prefix": "blocked", "eligible": false }),
    ));

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/cases/protocol");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("protocol-cases.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&Value::Array(cases)).unwrap() + "\n",
    )
    .unwrap();
    println!("wrote {}", path.display());
}
