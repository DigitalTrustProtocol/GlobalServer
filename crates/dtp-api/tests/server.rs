//! End-to-end: a real `dtp-global` server on a random port with a temp data
//! dir, driven over WebSocket and HTTP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

use dtp_api::config::{Access, Config, MemberCfg};
use dtp_api::{ServerHandle, start};
use dtp_model::statement::StatementBuilder;
use dtp_model::{
    Event, KIND_AUTH, KIND_DELETION, KIND_IDENTITY, Keys, Subject, SubjectType, encode_npub,
};
use dtp_store::RedbStore;

const T: u64 = 1_700_000_000;

fn writer() -> Keys {
    Keys::from_seed("sync-writer")
}

fn config(reads: Access) -> Config {
    let mut c = Config::default();
    c.server.listen = "127.0.0.1:0".into();
    c.admin.listen = Some("127.0.0.1:0".into());
    c.auth.reads = reads;
    c.auth.members = vec![
        MemberCfg {
            pubkey: writer().pubkey().into(),
            roles: vec!["write".into()],
        },
        MemberCfg {
            pubkey: Keys::from_seed("reader-member").pubkey().into(),
            roles: vec!["read".into()],
        },
    ];
    c.guardrails.max_connections = 64;
    c
}

async fn boot(dir: &std::path::Path, cfg: Config) -> ServerHandle {
    let store = RedbStore::open(&dir.join("events.redb")).unwrap();
    start(cfg, Arc::new(store), Keys::from_seed("server"))
        .await
        .unwrap()
}

struct Client {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    challenge: String,
    url: String,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Client {
        let url = format!("ws://{addr}/");
        let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let mut c = Client {
            ws,
            challenge: String::new(),
            url,
        };
        let first = c.recv().await;
        assert_eq!(first[0], "AUTH");
        c.challenge = first[1].as_str().unwrap().to_string();
        c
    }

    async fn send(&mut self, v: Value) {
        self.ws
            .send(Message::Text(v.to_string().into()))
            .await
            .unwrap();
    }

    async fn recv(&mut self) -> Value {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), self.ws.next())
                .await
                .expect("timed out waiting for a message")
                .expect("socket closed")
                .unwrap();
            if let Message::Text(t) = msg {
                return serde_json::from_str(t.as_str()).unwrap();
            }
        }
    }

    /// Receives until `pred` matches (other messages are dropped).
    async fn recv_until(&mut self, pred: impl Fn(&Value) -> bool) -> Value {
        loop {
            let v = self.recv().await;
            if pred(&v) {
                return v;
            }
        }
    }

    async fn auth(&mut self, keys: &Keys) -> Value {
        let ev = keys.sign_event(
            T.max(now()),
            KIND_AUTH,
            vec![
                vec!["relay".into(), self.url.clone()],
                vec!["challenge".into(), self.challenge.clone()],
            ],
            "",
        );
        let id = ev.id.clone();
        self.send(json!(["AUTH", ev])).await;
        self.recv_until(|v| v[0] == "OK" && v[1] == id).await
    }

    async fn event(&mut self, ev: &Event) -> (bool, String) {
        self.send(json!(["EVENT", ev])).await;
        let id = ev.id.clone();
        let ok = self.recv_until(|v| v[0] == "OK" && v[1] == id).await;
        (
            ok[2].as_bool().unwrap(),
            ok[3].as_str().unwrap().to_string(),
        )
    }

    async fn dtp(&mut self, id: &str, op: &str, params: Value) -> Value {
        self.send(json!(["DTP", id, op, params])).await;
        self.recv_until(|v| (v[0] == "DTP-OK" || v[0] == "DTP-ERR") && v[1] == id)
            .await
    }

    async fn req(&mut self, sub: &str, filter: Value) -> (Vec<Value>, Value) {
        self.send(json!(["REQ", sub, filter])).await;
        let mut events = Vec::new();
        loop {
            let v = self.recv().await;
            if v[1] != sub {
                continue;
            }
            match v[0].as_str() {
                Some("EVENT") => events.push(v[2].clone()),
                _ => return (events, v),
            }
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn p(keys: &Keys) -> Subject {
    Subject::new(SubjectType::P, keys.pubkey())
}

fn trust(author: &Keys, subject: Subject, value: &str, at: u64) -> Event {
    StatementBuilder::trust(subject, value)
        .scope("x.com")
        .context("identity")
        .sign(author, at)
}

async fn http(addr: SocketAddr, method: &str, path: &str, accept: &str) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: {accept}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn body_json(body: &str) -> Value {
    // Tolerate chunked transfer encoding: take the outermost JSON object.
    let start = body.find('{').unwrap();
    let end = body.rfind('}').unwrap();
    serde_json::from_str(&body[start..=end]).unwrap()
}

#[tokio::test]
async fn ingest_then_resolve_lookup_and_graph_ops() {
    let dir = tempfile::tempdir().unwrap();
    let server = boot(dir.path(), config(Access::Open)).await;
    let (alice, bob, carol, owner) = (
        Keys::from_seed("alice"),
        Keys::from_seed("bob"),
        Keys::from_seed("carol"),
        Keys::from_seed("owner"),
    );
    let x = Subject::new(SubjectType::I, "user:id:42");
    let npub = encode_npub(owner.pubkey()).unwrap();

    let mut w = Client::connect(server.addr).await;
    let ok = w.auth(&writer()).await;
    assert_eq!(ok[2], true, "{ok}");
    let events = vec![
        trust(&alice, p(&bob), "1", T),
        trust(&bob, p(&carol), "1", T),
        StatementBuilder::trust(x.clone(), "1")
            .scope("x.com")
            .context("identity")
            .hint(&npub)
            .sign(&bob, T),
        trust(&owner, p(&Keys::from_seed("zed")), "1", T),
        owner.sign_event(
            T,
            KIND_IDENTITY,
            vec![
                vec!["i".into(), "twitter:owner".into()],
                vec!["i".into(), "twitter_id:42".into()],
            ],
            "",
        ),
        StatementBuilder::rating(Subject::new(SubjectType::I, "post:id:7"), "80")
            .label("accurate", None)
            .sign(&bob, T),
        StatementBuilder::rating(Subject::new(SubjectType::I, "post:id:7"), "40").sign(&carol, T),
    ];
    for ev in &events {
        let (ok, msg) = w.event(ev).await;
        assert!(ok && msg.is_empty(), "{msg}");
    }

    let mut r = Client::connect(server.addr).await;
    let session = r
        .dtp("s", "session.update", json!({ "defaults": { "rootPubkey": alice.pubkey(), "bindingMode": "strict", "bounds": { "maxDepth": 4 } } }))
        .await;
    assert_eq!(session[0], "DTP-OK");

    let batch = r
        .dtp("b1", "trust.batch", json!({ "items": [
            { "key": "carol", "subject": { "type": "p", "value": carol.pubkey() }, "context": "identity" },
            { "key": "x", "subject": { "type": "i", "value": "user:id:42" }, "context": "identity" },
            { "key": "zed", "subject": { "type": "p", "value": Keys::from_seed("zed").pubkey() }, "context": "identity" },
            { "key": "nobody", "subject": { "type": "p", "value": "00".repeat(32) }, "context": "identity" }
        ] }))
        .await;
    assert_eq!(batch[0], "DTP-OK", "{batch}");
    let results = &batch[2]["results"];
    assert_eq!(results["carol"]["degree"], 2);
    assert_eq!(results["carol"]["resolution"], "trusted");
    assert_eq!(results["x"]["degree"], 2);
    assert_eq!(results["x"]["binding"]["pubkey"], owner.pubkey());
    assert_eq!(results["x"]["binding"]["confirmed"], true);
    assert_eq!(
        results["zed"]["degree"], 3,
        "strict bind confirmed by 10011 makes owner a hop"
    );
    assert_eq!(results["nobody"]["connected"], false);

    // Bob (level 1) rates at degree 2; Carol (level 2) is farther and ignored.
    let rating = r
        .dtp(
            "r1",
            "rating.query",
            json!({ "subject": { "type": "i", "value": "post:id:7" } }),
        )
        .await;
    assert_eq!(rating[2]["claimCount"], 1, "{rating}");
    assert_eq!(rating[2]["degree"], 2);
    assert_eq!(rating[2]["averageScore"], 80);

    let incoming = r
        .dtp("l1", "lookup.incoming", json!({ "keys": [format!("p:{}", carol.pubkey())], "context": "identity", "withTotals": true }))
        .await;
    assert_eq!(
        incoming[2]["items"].as_array().unwrap().len(),
        1,
        "{incoming}"
    );
    assert_eq!(incoming[2]["totals"]["trust"], 1);
    let counts = r
        .dtp(
            "l2",
            "lookup.counts",
            json!({ "keys": ["i:post:id:7"], "direction": "incoming", "kinds": [32014] }),
        )
        .await;
    assert_eq!(counts[2]["counts"]["i:post:id:7"]["ratings"], 2);
    let batch = r
        .dtp("l3", "lookup.batch", json!({ "queries": [
            { "id": "out", "op": "outgoing", "params": { "keys": [format!("p:{}", bob.pubkey())], "context": "identity" } },
            { "id": "bad", "op": "nope", "params": {} }
        ] }))
        .await;
    assert_eq!(
        batch[2]["results"]["out"]["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(batch[2]["errors"]["bad"].is_string());

    let hood = r
        .dtp(
            "n1",
            "graph.neighborhood",
            json!({ "centerId": format!("p:{}", bob.pubkey()) }),
        )
        .await;
    // alice → bob, bob → carol / user:id:42, and bob's rating arrow to post:id:7.
    assert_eq!(hood[2]["nodes"].as_array().unwrap().len(), 5, "{hood}");
    assert!(
        hood[2]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == 32014 && e["value"] == 1)
    );

    let frontier = r
        .dtp(
            "f1",
            "graph.frontier",
            json!({ "roots": [alice.pubkey()], "maxDepth": 4 }),
        )
        .await;
    let authors: Vec<&str> = frontier[2]["authors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["pubkey"].as_str().unwrap())
        .collect();
    assert!(authors.contains(&owner.pubkey()), "{frontier}");

    let field = r.dtp("g1", "graph.field", json!({})).await;
    assert_eq!(field[2]["levels"][0], json!([alice.pubkey()]), "{field}");
    assert_eq!(field[2]["levels"][1], json!([bob.pubkey()]));

    let claims = r
        .dtp("c1", "identity.claims", json!({ "twitterId": "42" }))
        .await;
    assert_eq!(claims[2]["claims"][0]["pubkey"], owner.pubkey());

    let info = r.dtp("i1", "info", json!({})).await;
    assert_eq!(info[2]["model"], "dtp-wot/1");
    assert!(info[2]["graphVersion"].as_u64().unwrap() > 1);

    let unknown = r.dtp("u1", "nope.op", json!({})).await;
    assert_eq!(unknown[0], "DTP-ERR");
    assert_eq!(unknown[2], "invalid");
    let bad = r
        .dtp(
            "q1",
            "trust.query",
            json!({ "subject": { "type": "z", "value": "x" } }),
        )
        .await;
    assert_eq!(bad[2], "invalid");

    server.shutdown().await;
}

#[tokio::test]
async fn write_access_is_whitelisted() {
    let dir = tempfile::tempdir().unwrap();
    let server = boot(dir.path(), config(Access::Open)).await;
    let ev = trust(
        &Keys::from_seed("alice"),
        p(&Keys::from_seed("bob")),
        "1",
        T,
    );

    let mut anon = Client::connect(server.addr).await;
    let (ok, msg) = anon.event(&ev).await;
    assert!(!ok);
    assert!(msg.starts_with("auth-required:"), "{msg}");

    let mut stranger = Client::connect(server.addr).await;
    assert_eq!(stranger.auth(&Keys::from_seed("stranger")).await[2], true);
    let (ok, msg) = stranger.event(&ev).await;
    assert!(!ok);
    assert!(msg.starts_with("restricted:"), "{msg}");

    // A bad AUTH (wrong challenge) is refused.
    let mut bad = Client::connect(server.addr).await;
    bad.challenge = "wrong".into();
    let answer = bad.auth(&writer()).await;
    assert_eq!(answer[2], false);
    assert!(answer[3].as_str().unwrap().starts_with("invalid:"));

    let mut w = Client::connect(server.addr).await;
    w.auth(&writer()).await;
    assert_eq!(w.event(&ev).await, (true, String::new()));
    let (ok, msg) = w.event(&ev).await;
    assert!(ok && msg.starts_with("duplicate:"), "{msg}");
    let older = trust(
        &Keys::from_seed("alice"),
        p(&Keys::from_seed("bob")),
        "-1",
        T - 10,
    );
    let (ok, msg) = w.event(&older).await;
    assert!(ok && msg.starts_with("duplicate:"), "{msg}");

    // Validation still applies to whitelisted writers.
    let mut forged = ev.clone();
    forged.content = "changed".into();
    forged.id = Event::compute_id(
        &forged.pubkey,
        forged.created_at,
        forged.kind,
        &forged.tags,
        &forged.content,
    );
    let (ok, msg) = w.event(&forged).await;
    assert!(!ok && msg.starts_with("invalid:"), "{msg}");
    let kind1 = Keys::from_seed("alice").sign_event(T, 1, vec![], "hi");
    let (ok, msg) = w.event(&kind1).await;
    assert!(!ok && msg.starts_with("blocked:"), "{msg}");
    let other_scope = StatementBuilder::trust(p(&Keys::from_seed("bob")), "1")
        .scope("nostr")
        .sign(&Keys::from_seed("alice"), T);
    let (ok, msg) = w.event(&other_scope).await;
    assert!(!ok && msg.starts_with("blocked:"), "{msg}");

    server.shutdown().await;
}

#[tokio::test]
async fn nip09_deletion_req_ids_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Keys::from_seed("alice");
    let bob = Keys::from_seed("bob");
    let e1 = trust(&alice, p(&bob), "1", T);
    let keep = trust(&alice, p(&Keys::from_seed("carol")), "1", T);
    {
        let server = boot(dir.path(), config(Access::Open)).await;
        let mut w = Client::connect(server.addr).await;
        w.auth(&writer()).await;
        assert!(w.event(&e1).await.0);
        assert!(w.event(&keep).await.0);

        let mut r = Client::connect(server.addr).await;
        let (events, end) = r.req("ids", json!({ "ids": [e1.id, keep.id] })).await;
        assert_eq!(events.len(), 2);
        assert_eq!(end[0], "EOSE");
        let (events, _) = r
            .req(
                "by-author",
                json!({ "authors": [alice.pubkey()], "kinds": [32009] }),
            )
            .await;
        assert_eq!(events.len(), 2);
        let (_, closed) = r.req("bad", json!({ "#p": [bob.pubkey()] })).await;
        assert_eq!(closed[0], "CLOSED");
        assert!(closed[2].as_str().unwrap().starts_with("unsupported:"));

        let del = alice.sign_event(
            T + 5,
            KIND_DELETION,
            vec![
                vec!["e".into(), e1.id.clone()],
                vec!["k".into(), "32009".into()],
            ],
            "",
        );
        assert_eq!(w.event(&del).await, (true, String::new()));
        let q = r
            .dtp("t", "trust.query", json!({ "rootPubkey": alice.pubkey(), "subject": { "type": "p", "value": bob.pubkey() }, "context": "identity" }))
            .await;
        assert_eq!(q[2]["connected"], false, "{q}");
        let (ok, msg) = w.event(&e1).await;
        assert!(!ok && msg.starts_with("blocked:"), "{msg}");
        let (events, _) = r.req("ids2", json!({ "ids": [e1.id] })).await;
        assert!(events.is_empty());
        server.shutdown().await;
    }
    // Restart: winners and floors come back from the store.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let server = boot(dir.path(), config(Access::Open)).await;
    let mut r = Client::connect(server.addr).await;
    let q = r
        .dtp("t", "trust.query", json!({ "rootPubkey": alice.pubkey(), "subject": { "type": "p", "value": Keys::from_seed("carol").pubkey() }, "context": "identity" }))
        .await;
    assert_eq!(q[2]["degree"], 1, "{q}");
    let mut w = Client::connect(server.addr).await;
    w.auth(&writer()).await;
    let (ok, msg) = w.event(&e1).await;
    assert!(
        !ok && msg.starts_with("blocked:"),
        "deleted event stays deleted after restart: {msg}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn membership_list_pushes_and_reads_auth() {
    let dir = tempfile::tempdir().unwrap();
    let server = boot(dir.path(), config(Access::Members)).await;
    let server_keys = Keys::from_seed("server");

    let mut anon = Client::connect(server.addr).await;
    let refused = anon.dtp("1", "info", json!({})).await;
    assert_eq!(refused[0], "DTP-ERR");
    assert_eq!(refused[2], "auth-required");
    let (_, closed) = anon.req("m", json!({ "kinds": [13534] })).await;
    assert_eq!(closed[0], "CLOSED");

    let mut member = Client::connect(server.addr).await;
    member.auth(&Keys::from_seed("reader-member")).await;
    let (events, _) = member.req("m", json!({ "kinds": [13534, 33534] })).await;
    assert_eq!(events.len(), 4);
    let list = events.iter().find(|e| e["kind"] == 13534).unwrap();
    assert_eq!(list["pubkey"], server_keys.pubkey());
    assert!(
        list["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t[1] == writer().pubkey() && t[2] == "write")
    );
    assert!(Event::from_value(list).unwrap().verify().is_ok());

    let sub = member
        .dtp("s", "subscribe", json!({ "topics": ["graph"] }))
        .await;
    assert_eq!(sub[2]["topics"], json!(["graph"]));
    let mut w = Client::connect(server.addr).await;
    w.auth(&writer()).await;
    let ev = trust(
        &Keys::from_seed("alice"),
        p(&Keys::from_seed("bob")),
        "1",
        T,
    );
    assert!(w.event(&ev).await.0);
    let push = member.recv_until(|v| v[0] == "DTP-PUSH").await;
    assert_eq!(push[1], "graph");
    let subjects = push[2]["changed"]["subjects"].as_array().unwrap();
    assert!(
        subjects.contains(&json!(format!("p:{}", Keys::from_seed("bob").pubkey()))),
        "{push}"
    );

    // Cancel: an unknown request id is ignored; a completed one too.
    member.send(json!(["DTP-CANCEL", "none"])).await;
    let info = member.dtp("i", "info", json!({})).await;
    assert_eq!(info[0], "DTP-OK");
    server.shutdown().await;
}

#[tokio::test]
async fn busy_when_in_flight_limit_is_zero() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(Access::Open);
    cfg.guardrails.max_in_flight = 0;
    let server = boot(dir.path(), cfg).await;
    let mut r = Client::connect(server.addr).await;
    let busy = r.dtp("1", "info", json!({})).await;
    assert_eq!(busy[0], "DTP-ERR");
    assert_eq!(busy[2], "busy");
    server.shutdown().await;
}

#[tokio::test]
async fn http_nip11_health_admin_and_metrics() {
    let dir = tempfile::tempdir().unwrap();
    let server = boot(dir.path(), config(Access::Open)).await;
    let (status, body) = http(server.addr, "GET", "/", "application/nostr+json").await;
    assert_eq!(status, 200);
    let doc = body_json(&body);
    assert_eq!(doc["self"], Keys::from_seed("server").pubkey());
    assert_eq!(doc["limitation"]["restricted_writes"], true);
    assert_eq!(doc["limitation"]["auth_required"], false);
    assert_eq!(doc["dtp"]["api"], "v1");
    assert_eq!(
        doc["dtp"]["capabilities"].as_array().unwrap().len(),
        dtp_protocol::CAPABILITIES.len()
    );
    assert_eq!(http(server.addr, "GET", "/healthz", "*/*").await.0, 200);
    assert_eq!(http(server.addr, "GET", "/readyz", "*/*").await.0, 200);
    assert_eq!(
        http(server.addr, "POST", "/", "application/nostr+json+rpc")
            .await
            .0,
        501
    );

    let (status, body) = http(
        server.admin_addr,
        "GET",
        "/admin/api/telemetry",
        "application/json",
    )
    .await;
    assert_eq!(status, 200);
    let t = body_json(&body);
    for key in [
        "schema",
        "generatedAt",
        "server",
        "health",
        "graph",
        "ingest",
        "sources",
        "queries",
        "connections",
        "memory",
        "roots",
        "logs",
        "config",
        "alerts",
    ] {
        assert!(t.get(key).is_some(), "telemetry misses {key}");
    }
    assert_eq!(t["schema"], "dtp-telemetry/1");
    assert_eq!(t["server"]["kind"], "global");
    assert!(t["sources"]["relays"].is_null());
    let (status, metrics) = http(server.admin_addr, "GET", "/metrics", "text/plain").await;
    assert_eq!(status, 200);
    for name in [
        "dtp_up 1",
        "dtp_ready 1",
        "dtp_graph_version",
        "dtp_graph_nodes",
        "dtp_graph_edges{kind=\"32009\"}",
    ] {
        assert!(metrics.contains(name), "metrics miss {name}");
    }
    let (status, page) = http(server.admin_addr, "GET", "/", "text/html").await;
    assert_eq!(status, 200);
    assert!(page.contains("dtp-global"));
    server.shutdown().await;
}
