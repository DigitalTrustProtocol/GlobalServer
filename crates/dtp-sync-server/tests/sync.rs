//! `dtp-sync` against a mock relay and a real `dtp-global` resolver.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use dtp_api::config::{Config, MemberCfg};
use dtp_model::statement::StatementBuilder;
use dtp_model::{Event, KIND_DELETION, KIND_IDENTITY, Keys, Subject, SubjectType};
use dtp_sync_server::{SyncConfig, start};

const T: u64 = 1_700_000_000;

fn matches(filter: &Value, e: &Event) -> bool {
    let kinds_ok = filter["kinds"]
        .as_array()
        .is_none_or(|k| k.iter().any(|k| k.as_u64() == Some(u64::from(e.kind))));
    let until_ok = filter["until"].as_u64().is_none_or(|u| e.created_at <= u);
    let since_ok = filter["since"].as_u64().is_none_or(|s| e.created_at >= s);
    kinds_ok && until_ok && since_ok
}

/// A tiny relay: answers REQ with stored events (newest first, `limit`), EOSE,
/// and on the live subscription pushes `live` events after EOSE.
async fn mock_relay(stored: Vec<Event>, live: Vec<Event>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (stored, live) = (stored.clone(), live.clone());
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    let Message::Text(text) = msg else { continue };
                    let v: Value = serde_json::from_str(text.as_str()).unwrap();
                    if v[0] != "REQ" {
                        continue;
                    }
                    let sub = v[1].as_str().unwrap().to_string();
                    let filters: Vec<Value> = v.as_array().unwrap()[2..].to_vec();
                    let limit = filters
                        .iter()
                        .filter_map(|f| f["limit"].as_u64())
                        .min()
                        .unwrap_or(u64::MAX) as usize;
                    let mut out: Vec<&Event> = stored
                        .iter()
                        .filter(|e| filters.iter().any(|f| matches(f, e)))
                        .collect();
                    out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
                    for e in out.into_iter().take(limit) {
                        let _ = ws
                            .send(Message::Text(json!(["EVENT", sub, e]).to_string().into()))
                            .await;
                    }
                    let _ = ws
                        .send(Message::Text(json!(["EOSE", sub]).to_string().into()))
                        .await;
                    if sub == "dtp-live" {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        for e in &live {
                            let _ = ws
                                .send(Message::Text(json!(["EVENT", sub, e]).to_string().into()))
                                .await;
                        }
                    }
                }
            });
        }
    });
    addr
}

fn trust(author: &Keys, subject: &Keys, at: u64) -> Event {
    StatementBuilder::trust(Subject::new(SubjectType::P, subject.pubkey()), "1")
        .scope("x.com")
        .context("identity")
        .sign(author, at)
}

#[tokio::test]
async fn backfill_and_live_reach_the_resolver() {
    let sync_keys = Keys::from_seed("dtp-sync-writer");
    let (alice, bob, carol, dave) = (
        Keys::from_seed("alice"),
        Keys::from_seed("bob"),
        Keys::from_seed("carol"),
        Keys::from_seed("dave"),
    );
    let e1 = trust(&alice, &bob, T);
    let e2 = trust(&bob, &carol, T + 1);
    let claim = carol.sign_event(
        T + 2,
        KIND_IDENTITY,
        vec![
            vec!["i".into(), "twitter:carol".into()],
            vec!["i".into(), "twitter_id:7".into()],
        ],
        "",
    );
    let doomed = trust(&alice, &dave, T + 3);
    let deletion = alice.sign_event(
        T + 4,
        KIND_DELETION,
        vec![
            vec!["e".into(), doomed.id.clone()],
            vec!["k".into(), "32009".into()],
        ],
        "",
    );
    let mut forged = trust(&alice, &carol, T + 5);
    forged.content = "tampered".into();
    let note = alice.sign_event(T + 6, 1, vec![], "not a held kind");
    let live_event = trust(&carol, &dave, T + 7);
    let relay = mock_relay(
        vec![
            e1.clone(),
            e2.clone(),
            claim.clone(),
            doomed.clone(),
            deletion.clone(),
            forged.clone(),
            note.clone(),
        ],
        vec![live_event.clone()],
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.server.listen = "127.0.0.1:0".into();
    cfg.admin.listen = Some("127.0.0.1:0".into());
    cfg.auth.members = vec![MemberCfg {
        pubkey: sync_keys.pubkey().into(),
        roles: vec!["write".into()],
    }];
    let store = dtp_store::RocksDbStore::open(&dir.path().join("events")).unwrap();
    let resolver = dtp_api::start(cfg, Arc::new(store), Keys::from_seed("server"))
        .await
        .unwrap();
    let target = format!("ws://{}/", resolver.addr);

    let sync_cfg = SyncConfig {
        relays: vec![format!("ws://{relay}/")],
        targets: vec![target.clone()],
        backfill: dtp_sync_server::BackfillCfg {
            enabled: true,
            since: None,
            page: 2,
            max_pages: 50,
        },
        ..SyncConfig::default()
    };
    let sync = start(sync_cfg, sync_keys);

    let wanted = [&e1, &e2, &claim, &live_event];
    let mut done = false;
    for _ in 0..100 {
        let g = resolver.state.graph.load();
        let has = |e: &Event| g.has_id(&dtp_model::hex32(&e.id).unwrap());
        if wanted.iter().all(|e| has(e)) && !has(&doomed) {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "resolver did not receive the synced events");
    let g = resolver.state.graph.load();
    let has = |e: &Event| g.has_id(&dtp_model::hex32(&e.id).unwrap());
    assert!(
        !has(&forged),
        "forged event must be dropped by the pre-filter"
    );
    assert!(!has(&note));
    assert!(!has(&doomed), "NIP-09 deletion applied");
    assert_eq!(g.claims_for("7").len(), 1);
    let stats = sync.stats.target(&target);
    assert!(stats.accepted >= 5, "{stats:?}");
    // The relay filters by kind, so only the forged event reaches the pre-filter.
    assert!(
        sync.stats
            .dropped_invalid
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );

    sync.shutdown().await;
    resolver.shutdown().await;
}

#[tokio::test]
async fn unauthorized_writer_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.server.listen = "127.0.0.1:0".into();
    cfg.admin.listen = Some("127.0.0.1:0".into());
    let store = dtp_store::RocksDbStore::open(&dir.path().join("events")).unwrap();
    let resolver = dtp_api::start(cfg, Arc::new(store), Keys::from_seed("server"))
        .await
        .unwrap();
    let url = format!("ws://{}/", resolver.addr);
    let mut pusher = dtp_relay::Pusher::connect(&url, &Keys::from_seed("not-a-member"))
        .await
        .unwrap();
    let e = trust(&Keys::from_seed("alice"), &Keys::from_seed("bob"), T);
    let answers = pusher.push(std::slice::from_ref(&e)).await.unwrap();
    assert_eq!(answers.len(), 1);
    assert!(!answers[0].1);
    assert!(answers[0].2.starts_with("restricted:"), "{:?}", answers[0]);
    resolver.shutdown().await;
}
