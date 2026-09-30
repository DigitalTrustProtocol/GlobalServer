//! Session suite: starts a real `dtp-global` (random port, temp data dir)
//! per script and replays it over one WebSocket, like `runSession()` in
//! TrustGraph `@dtp/conformance`: the server's `AUTH` challenge is ignored,
//! each step sends one frame and reads exactly `expect.length` frames
//! (5 s per step); frames left over carry into the next step.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use dtp_api::config::{Access, Config, MemberCfg};
use dtp_api::start;
use dtp_conformance::session::{
    Features, Session, SessionReport, StepOutcome, judge, load_sessions, plan_step, wants_push,
};
use dtp_model::Keys;
use dtp_store::RedbStore;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn access(v: &Value) -> Result<Access, String> {
    match v.as_str() {
        Some("open") => Ok(Access::Open),
        Some("members") => Ok(Access::Members),
        _ => Err(format!("unsupported access value {v}")),
    }
}

fn members(v: &Value) -> Result<Vec<MemberCfg>, String> {
    serde_json::from_value(v.clone()).map_err(|e| format!("members: {e}"))
}

/// Maps a session `config` onto the server configuration. Unknown keys are
/// an error so a new session setting is never silently ignored.
fn server_config(session: &Session) -> Result<Config, String> {
    let mut c = Config::default();
    c.server.listen = "127.0.0.1:0".into();
    c.admin.listen = Some("127.0.0.1:0".into());
    for (key, v) in session.config() {
        match key.as_str() {
            "auth.reads" => c.auth.reads = access(&v)?,
            "auth.writes" => c.auth.writes = access(&v)?,
            "auth.members" | "members" => c.auth.members = members(&v)?,
            "auth.admins" | "admins" => {
                c.auth.admins = serde_json::from_value(v).map_err(|e| format!("admins: {e}"))?
            }
            "scopeProfile" => {
                c.model.scope_profile = v.as_str().ok_or("scopeProfile: string")?.into()
            }
            "bindingMode" => c.model.binding_mode = v.as_str().ok_or("bindingMode: string")?.into(),
            "followTrustThreshold" => {
                c.model.follow_trust_threshold =
                    v.as_u64().ok_or("followTrustThreshold: integer")?
            }
            "followTrustRed" => {
                c.model.follow_trust_red = v.as_u64().ok_or("followTrustRed: integer")?
            }
            "limits.maxReachedNodes" => {
                c.guardrails.max_reached_nodes =
                    v.as_u64().ok_or("limits.maxReachedNodes: integer")? as usize
            }
            "limits.maxWalkRecords" => {
                c.guardrails.max_walk_records =
                    v.as_u64().ok_or("limits.maxWalkRecords: integer")? as usize
            }
            other => return Err(format!("unsupported session config key {other}")),
        }
    }
    Ok(c)
}

struct Conn {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    inbox: VecDeque<Value>,
}

fn is_push(frame: &Value) -> bool {
    frame.get(0).and_then(Value::as_str) == Some("DTP-PUSH")
}

impl Conn {
    async fn send(&mut self, frame: &Value) {
        self.ws
            .send(Message::Text(frame.to_string().into()))
            .await
            .unwrap();
    }

    /// Reads until `count` frames are queued (5 s); `DTP-PUSH` frames are
    /// dropped unless the step expects one, and leftovers carry over.
    async fn collect(&mut self, count: usize, wants_push: bool) -> Vec<Value> {
        if !wants_push {
            self.inbox.retain(|f| !is_push(f));
        }
        let until = Instant::now() + STEP_TIMEOUT;
        while self.inbox.len() < count {
            let Ok(Some(Ok(msg))) = tokio::time::timeout_at(until, self.ws.next()).await else {
                break;
            };
            if let Message::Text(t) = msg
                && let Ok(frame) = serde_json::from_str::<Value>(t.as_str())
                && frame.get(0).and_then(Value::as_str) != Some("AUTH")
                && (wants_push || !is_push(&frame))
            {
                self.inbox.push_back(frame);
            }
        }
        let n = count.min(self.inbox.len());
        self.inbox.drain(..n).collect()
    }
}

async fn run_session(session: &Session) -> SessionReport {
    let mut report = SessionReport {
        id: session.id().to_string(),
        ..Default::default()
    };
    let cfg = match server_config(session) {
        Ok(c) => c,
        Err(e) => {
            report.steps.push((0, None, StepOutcome::Fail(vec![e])));
            return report;
        }
    };
    let dir = tempfile::tempdir().unwrap();
    let store = RedbStore::open(&dir.path().join("events.redb")).unwrap();
    let server = start(cfg, Arc::new(store), Keys::from_seed("server"))
        .await
        .unwrap();
    let url = format!("ws://{}/", server.addr);
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let mut conn = Conn {
        ws,
        inbox: VecDeque::new(),
    };
    let mut features = None;
    if session.needs_features() {
        conn.send(&json!(["DTP", "$features", "info", {}])).await;
        let got = conn.collect(1, false).await;
        features = got
            .first()
            .filter(|f| f[0] == "DTP-OK" && f[1] == "$features")
            .and_then(|f| Features::from_info(&f[2]));
        if features.is_none() {
            let e = format!("info did not answer with capabilities: {got:?}");
            report.steps.push((0, None, StepOutcome::Fail(vec![e])));
        }
    }
    for (i, step) in session.steps().iter().enumerate() {
        let note = step.get("note").and_then(Value::as_str).map(String::from);
        let Some(expected) = plan_step(session, step, features.as_ref()) else {
            report.steps.push((i, note, StepOutcome::Skip));
            continue;
        };
        conn.send(step.get("send").unwrap_or(&Value::Null)).await;
        let got = conn.collect(expected.len(), wants_push(expected)).await;
        report.steps.push((i, note, judge(step, expected, &got)));
    }
    let _ = conn.ws.close(None).await;
    server.shutdown().await;
    report
}

async fn run_suite(dir: &Path) -> Vec<SessionReport> {
    let sessions = load_sessions(dir).unwrap_or_else(|e| panic!("{e}"));
    let mut reports = Vec::new();
    for s in &sessions {
        let r = run_session(s).await;
        println!("{} ({})", r.summary(), s.file.display());
        reports.push(r);
    }
    reports
}

/// Pinned copies of the TrustGraph scripts: must always pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_sessions_pass() {
    let reports = run_suite(&workspace().join("tests")).await;
    assert!(!reports.is_empty(), "no local session scripts");
    for r in &reports {
        assert_eq!(r.failed(), 0, "{}", r.summary());
    }
}

/// The live TrustGraph suite. Report-only unless `DTP_CORPUS_STRICT=1`,
/// because it is written concurrently (same rule as the model corpus).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trustgraph_sessions() {
    let dir = workspace().join("..").join("TrustGraph").join("corpus");
    if !dir.exists() {
        println!("TrustGraph corpus not present at {}", dir.display());
        return;
    }
    let reports = run_suite(&dir).await;
    if std::env::var("DTP_CORPUS_STRICT").as_deref() == Ok("1") {
        for r in &reports {
            assert_eq!(r.failed(), 0, "{}", r.summary());
        }
    }
}
