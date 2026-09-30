//! One WebSocket connection: NIP-01 framing, NIP-42, ingest with
//! backpressure, limited REQ, pipelined DTP operations, pushes, keepalive.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde_json::{Map, Value, json};
use tokio::sync::{Notify, broadcast, mpsc, oneshot};

use dtp_model::Event;
use dtp_protocol::{ClientMsg, ReqFilter, parse_client, parse_filter};

use crate::metrics::{WriterStat, now_f64};
use crate::ops::{OpError, execute, is_graph_op};
use crate::state::{AppState, GraphChange};
use crate::writer::{IngestJob, WriterMsg, prepare};

const PING_EVERY: Duration = Duration::from_secs(20);
const PONG_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_READER: Duration = Duration::from_secs(300);
const PUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Outgoing queue with the `maxUnsentOutput` guard.
#[derive(Clone)]
struct Out {
    tx: mpsc::UnboundedSender<(Message, usize)>,
    unsent: Arc<AtomicUsize>,
    max: usize,
    slow: Arc<AtomicBool>,
}

impl Out {
    fn text(&self, text: String) {
        let len = text.len();
        if self.unsent.fetch_add(len, Ordering::Relaxed) + len > self.max {
            self.slow.store(true, Ordering::Relaxed);
            return;
        }
        let _ = self.tx.send((Message::Text(text.into()), len));
    }

    fn raw(&self, message: Message) {
        let _ = self.tx.send((message, 0));
    }
}

/// Per-connection context.
pub struct ConnInfo {
    pub ip: IpAddr,
    pub origin_class: &'static str,
    pub relay_urls: Vec<String>,
}

struct Conn {
    id: u64,
    state: Arc<AppState>,
    out: Out,
    challenge: String,
    authed: Vec<String>,
    role: &'static str,
    origin_class: &'static str,
    relay_urls: Vec<String>,
    defaults: Arc<Mutex<Map<String, Value>>>,
    topics: BTreeSet<String>,
    in_flight: Arc<AtomicUsize>,
    pending: Arc<AtomicUsize>,
    ok_notify: Arc<Notify>,
    cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    writer_slots: Vec<String>,
    last_activity: Instant,
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub async fn handle_socket(socket: WebSocket, state: Arc<AppState>, info: ConnInfo) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<(Message, usize)>();
    let out = Out {
        tx,
        unsent: Arc::new(AtomicUsize::new(0)),
        max: state.limits.max_unsent_output,
        slow: Arc::new(AtomicBool::new(false)),
    };
    let unsent = out.unsent.clone();
    let sender = tokio::spawn(async move {
        while let Some((message, len)) = rx.recv().await {
            let closing = matches!(message, Message::Close(_));
            if sink.send(message).await.is_err() {
                break;
            }
            unsent.fetch_sub(len, Ordering::Relaxed);
            if closing {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let mut conn = Conn {
        id: state.next_conn.fetch_add(1, Ordering::Relaxed),
        state: state.clone(),
        out: out.clone(),
        challenge: random_hex(16),
        authed: Vec::new(),
        role: "anonymous_reader",
        origin_class: info.origin_class,
        relay_urls: info.relay_urls,
        defaults: Arc::new(Mutex::new(Map::new())),
        topics: BTreeSet::new(),
        in_flight: Arc::new(AtomicUsize::new(0)),
        pending: Arc::new(AtomicUsize::new(0)),
        ok_notify: Arc::new(Notify::new()),
        cancels: Arc::new(Mutex::new(HashMap::new())),
        writer_slots: Vec::new(),
        last_activity: Instant::now(),
    };
    state.metrics.connection(conn.role, conn.origin_class, 1);
    out.text(dtp_protocol::auth_challenge(&conn.challenge));

    let mut pushes = state.pushes.subscribe();
    let mut stop = state.shutdown.subscribe();
    let mut pending_push: Option<(u64, BTreeSet<String>, bool)> = None;
    let mut last_push = Instant::now() - PUSH_INTERVAL;
    let mut last_ping = Instant::now();
    let mut last_pong = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let max_pending = state.limits.max_pending_oks;

    loop {
        let can_read = conn.pending.load(Ordering::Relaxed) < max_pending;
        tokio::select! {
            message = stream.next(), if can_read => {
                match message {
                    Some(Ok(Message::Text(text))) => {
                        conn.last_activity = Instant::now();
                        conn.handle_text(text.as_str());
                    }
                    Some(Ok(Message::Binary(_))) => out.text(dtp_protocol::notice("invalid: binary frames are not supported")),
                    Some(Ok(Message::Ping(payload))) => out.raw(Message::Pong(payload)),
                    Some(Ok(Message::Pong(_))) => last_pong = Instant::now(),
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                }
            }
            _ = conn.ok_notify.notified(), if !can_read => {}
            _ = stop.changed() => break,
            change = pushes.recv() => {
                match change {
                    Ok(change) => conn.queue_push(&mut pending_push, &change),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let version = state.graph.load().epoch();
                        pending_push = Some((version, BTreeSet::new(), true));
                    }
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
            _ = tick.tick() => {
                if out.slow.load(Ordering::Relaxed) {
                    state.metrics.slow_disconnects.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                if pending_push.is_some() && last_push.elapsed() >= PUSH_INTERVAL {
                    let (version, subjects, overflow) = pending_push.take().unwrap();
                    let mut data = json!({ "graphVersion": version });
                    if !overflow && subjects.len() <= 500 {
                        data["changed"] = json!({ "subjects": subjects });
                    }
                    out.text(dtp_protocol::dtp_push("graph", &data));
                    last_push = Instant::now();
                }
                if last_ping.elapsed() >= PING_EVERY {
                    out.raw(Message::Ping(Vec::new().into()));
                    last_ping = Instant::now();
                }
                if last_pong.elapsed() >= PONG_TIMEOUT {
                    break;
                }
                let busy = conn.in_flight.load(Ordering::Relaxed) > 0 || conn.pending.load(Ordering::Relaxed) > 0;
                if conn.writer_slots.is_empty() && !busy && conn.last_activity.elapsed() >= IDLE_READER {
                    break;
                }
            }
        }
    }

    state.metrics.connection(conn.role, conn.origin_class, -1);
    state.metrics.writer_update(conn.id, None);
    {
        let mut writers = state.writer_conns.lock().unwrap();
        for pk in &conn.writer_slots {
            if let Some(n) = writers.get_mut(pk) {
                *n = n.saturating_sub(1);
            }
        }
    }
    out.raw(Message::Close(None));
    drop(conn);
    drop(out);
    let _ = tokio::time::timeout(Duration::from_secs(2), sender).await;
}

impl Conn {
    fn queue_push(
        &self,
        pending: &mut Option<(u64, BTreeSet<String>, bool)>,
        change: &GraphChange,
    ) {
        if !self.topics.contains("graph") {
            return;
        }
        let entry = pending.get_or_insert_with(|| (change.version, BTreeSet::new(), false));
        entry.0 = change.version;
        if change.subjects.is_empty() {
            entry.2 = true;
        }
        entry.1.extend(change.subjects.iter().cloned());
        if entry.1.len() > 500 {
            entry.2 = true;
            entry.1.clear();
        }
    }

    fn handle_text(&mut self, text: &str) {
        match parse_client(text) {
            Err(notice) => self.out.text(dtp_protocol::notice(&notice)),
            Ok(ClientMsg::Event(value)) => self.on_event(value),
            Ok(ClientMsg::Auth(value)) => self.on_auth(value),
            Ok(ClientMsg::Req { sub, filters }) => self.on_req(sub, filters),
            Ok(ClientMsg::Close(_)) => {}
            Ok(ClientMsg::Dtp { req_id, op, params }) => self.on_dtp(req_id, op, params),
            Ok(ClientMsg::DtpCancel(req_id)) => {
                let key = req_id.to_string();
                if let Some(flag) = self.cancels.lock().unwrap().remove(&key) {
                    flag.store(true, Ordering::Relaxed);
                    self.out.text(dtp_protocol::dtp_err(
                        &req_id,
                        "cancelled",
                        "cancelled by the client",
                    ));
                }
            }
        }
    }

    fn set_role(&mut self) {
        let m = self.state.membership();
        let admins = &self.state.config.auth.admins;
        let role = if self
            .authed
            .iter()
            .any(|pk| admins.contains(pk) || m.has_role(pk, "admin"))
        {
            "admin"
        } else if self.authed.iter().any(|pk| m.has_role(pk, "write")) {
            "writer"
        } else if self.authed.iter().any(|pk| m.has_role(pk, "read")) {
            "member_reader"
        } else {
            "anonymous_reader"
        };
        if role != self.role {
            self.state
                .metrics
                .connection(self.role, self.origin_class, -1);
            self.state.metrics.connection(role, self.origin_class, 1);
            self.role = role;
        }
    }

    fn on_auth(&mut self, value: Value) {
        let now = self.state.server_now();
        match dtp_protocol::verify_auth(&value, &self.challenge, &self.relay_urls, now) {
            Err((id, message)) => self.out.text(dtp_protocol::ok(&id, false, &message)),
            Ok((id, pubkey)) => {
                if self.state.membership().has_role(&pubkey, "write")
                    && !self.writer_slots.contains(&pubkey)
                {
                    let mut writers = self.state.writer_conns.lock().unwrap();
                    let n = writers.entry(pubkey.clone()).or_default();
                    if *n >= self.state.limits.max_writer_connections {
                        drop(writers);
                        self.out.text(dtp_protocol::ok(
                            &id,
                            false,
                            "restricted: too many writer connections for this pubkey",
                        ));
                        return;
                    }
                    *n += 1;
                    self.writer_slots.push(pubkey.clone());
                    self.state.metrics.writer_update(
                        self.id,
                        Some(WriterStat {
                            pubkey: Some(pubkey.clone()),
                            connected_since: now_f64(),
                            events: 0,
                            rejects: 0,
                        }),
                    );
                }
                if !self.authed.contains(&pubkey) {
                    self.authed.push(pubkey);
                }
                self.state
                    .metrics
                    .authentications
                    .fetch_add(1, Ordering::Relaxed);
                self.set_role();
                self.out.text(dtp_protocol::ok(&id, true, ""));
            }
        }
    }

    fn on_event(&mut self, value: Value) {
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kind = value.get("kind").and_then(Value::as_u64).unwrap_or(0) as u32;
        let state = self.state.clone();
        let reject = |conn: &Conn, message: String, result: &'static str| {
            let prefix = message.split(':').next().map(str::to_string);
            state.metrics.ingest(kind, result, prefix.as_deref());
            state.metrics.writer_event(conn.id, true);
            conn.out.text(dtp_protocol::ok(&id, false, &message));
        };
        if let Err(message) = state.allowed(&state.config.auth.writes, &self.authed, "write") {
            return reject(self, message, "blocked");
        }
        if value.to_string().len() > state.config.ingest.max_event_bytes {
            return reject(self, "invalid: event too large".into(), "invalid");
        }
        let event = match Event::from_value(&value) {
            Ok(e) => e,
            Err(_) => {
                return reject(
                    self,
                    "invalid: event does not have a valid shape".into(),
                    "invalid",
                );
            }
        };
        if !dtp_protocol::is_ingest_kind(event.kind) {
            return reject(self, "blocked: kind not accepted".into(), "blocked");
        }
        self.pending.fetch_add(1, Ordering::Relaxed);
        state.metrics.pending_oks.fetch_add(1, Ordering::Relaxed);
        let out = self.out.clone();
        let pending = self.pending.clone();
        let notify = self.ok_notify.clone();
        let conn_id = self.id;
        tokio::spawn(async move {
            let profile = state.profile;
            let prepared_event = event.clone();
            let prepared = tokio::task::spawn_blocking(move || prepare(&prepared_event, profile))
                .await
                .unwrap_or_else(|_| Err((false, "error: validation failed".into(), "invalid")));
            let (ok, message) = match prepared {
                Err((ok, message, result)) => {
                    let prefix = message.split(':').next().map(str::to_string);
                    state.metrics.ingest(event.kind, result, prefix.as_deref());
                    (ok, message)
                }
                // Signatures are checked before slot reduction, so a forged
                // copy of a stored event is `invalid:`, never `duplicate:`.
                Ok(_)
                    if dtp_model::hex32(&event.id)
                        .is_some_and(|raw| state.graph.load().has_id(&raw)) =>
                {
                    state
                        .metrics
                        .ingest(event.kind, "duplicate", Some("duplicate"));
                    (true, "duplicate: already have this event".to_string())
                }
                Ok(payload) => {
                    let (reply, answer) = oneshot::channel();
                    let job = IngestJob {
                        event: event.clone(),
                        payload,
                        reply,
                    };
                    if state.ingest_tx.send(WriterMsg::Job(job)).await.is_err() {
                        (false, "error: ingest is shutting down".to_string())
                    } else {
                        answer
                            .await
                            .unwrap_or((false, "error: ingest failed".into()))
                    }
                }
            };
            state.metrics.writer_event(conn_id, !ok);
            out.text(dtp_protocol::ok(&event.id, ok, &message));
            pending.fetch_sub(1, Ordering::Relaxed);
            state.metrics.pending_oks.fetch_sub(1, Ordering::Relaxed);
            notify.notify_one();
        });
    }

    fn on_req(&mut self, sub: String, filters: Vec<Value>) {
        if let Err(message) =
            self.state
                .allowed(&self.state.config.auth.reads, &self.authed, "read")
        {
            return self.out.text(dtp_protocol::closed(&sub, &message));
        }
        let mut parsed = Vec::new();
        for f in &filters {
            match parse_filter(f) {
                Ok(p) => parsed.push(p),
                Err(message) => return self.out.text(dtp_protocol::closed(&sub, &message)),
            }
        }
        if parsed.is_empty() {
            return self
                .out
                .text(dtp_protocol::closed(&sub, "invalid: REQ needs a filter"));
        }
        let state = self.state.clone();
        let out = self.out.clone();
        tokio::spawn(async move {
            let membership = state.membership_events();
            let store = state.store.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut events: Vec<Event> = Vec::new();
                let mut seen = std::collections::HashSet::new();
                for f in parsed {
                    match f {
                        ReqFilter::Ids(ids) => {
                            for id in ids {
                                if let Ok(Some(e)) = store.event_by_id(&id) {
                                    events.push(e);
                                } else if let Some(e) = membership.iter().find(|e| e.id == id) {
                                    events.push(e.clone());
                                }
                            }
                        }
                        ReqFilter::Authors {
                            authors,
                            kinds,
                            limit,
                        } => {
                            for a in authors {
                                if let Ok(mut found) = store.events_by_author(&a, &kinds, limit) {
                                    events.append(&mut found);
                                }
                            }
                        }
                        ReqFilter::Membership { kinds } => {
                            events.extend(
                                membership
                                    .iter()
                                    .filter(|e| kinds.contains(&e.kind))
                                    .cloned(),
                            );
                        }
                    }
                }
                events.retain(|e| seen.insert(e.id.clone()));
                events
            })
            .await
            .unwrap_or_default();
            for e in &result {
                out.text(dtp_protocol::event(&sub, e));
            }
            out.text(dtp_protocol::eose(&sub));
        });
    }

    fn on_dtp(&mut self, req_id: Value, op: String, params: Value) {
        let metrics = &self.state.metrics;
        if let Err(message) =
            self.state
                .allowed(&self.state.config.auth.reads, &self.authed, "read")
        {
            let (code, text) = message
                .split_once(": ")
                .unwrap_or(("auth-required", message.as_str()));
            let code = if code == "restricted" {
                "restricted"
            } else {
                "auth-required"
            };
            metrics.op(&op, "invalid", None);
            return self.out.text(dtp_protocol::dtp_err(&req_id, code, text));
        }
        let Value::Object(params) = params else {
            metrics.op(&op, "invalid", None);
            return self.out.text(dtp_protocol::dtp_err(
                &req_id,
                "invalid",
                "params must be an object",
            ));
        };
        match op.as_str() {
            "session.update" => {
                let defaults = match params.get("defaults") {
                    Some(Value::Object(d)) => d.clone(),
                    None => Map::new(),
                    Some(_) => {
                        metrics.op(&op, "invalid", None);
                        return self.out.text(dtp_protocol::dtp_err(
                            &req_id,
                            "invalid",
                            "defaults must be an object",
                        ));
                    }
                };
                if let Some(root) = defaults.get("rootPubkey") {
                    match dtp_resolve::query::parse_pubkey(root, "rootPubkey") {
                        Ok(root) => self.state.touch_root(&root),
                        Err(e) => {
                            metrics.op(&op, "invalid", None);
                            return self
                                .out
                                .text(dtp_protocol::dtp_err(&req_id, "invalid", &e.0));
                        }
                    }
                }
                *self.defaults.lock().unwrap() = defaults.clone();
                metrics.op(&op, "ok", Some(0.0));
                self.out.text(dtp_protocol::dtp_ok(
                    &req_id,
                    &json!({ "defaults": defaults }),
                ));
            }
            "subscribe" | "unsubscribe" => {
                let topics: Vec<String> = params
                    .get("topics")
                    .and_then(Value::as_array)
                    .map(|t| {
                        t.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(bad) = topics
                    .iter()
                    .find(|t| !dtp_protocol::TOPICS.contains(&t.as_str()))
                {
                    metrics.op(&op, "invalid", None);
                    return self.out.text(dtp_protocol::dtp_err(
                        &req_id,
                        "invalid",
                        &format!("unknown topic {bad}"),
                    ));
                }
                for t in topics {
                    if op == "subscribe" {
                        self.topics.insert(t);
                    } else {
                        self.topics.remove(&t);
                    }
                }
                metrics.op(&op, "ok", Some(0.0));
                self.out.text(dtp_protocol::dtp_ok(
                    &req_id,
                    &json!({ "topics": self.topics }),
                ));
            }
            op_name if is_graph_op(op_name) => {
                if self
                    .cancels
                    .lock()
                    .unwrap()
                    .contains_key(&req_id.to_string())
                {
                    metrics.op(op_name, "invalid", None);
                    return self.out.text(dtp_protocol::dtp_err(
                        &req_id,
                        "invalid",
                        "reqId is already in flight on this connection",
                    ));
                }
                if self.in_flight.load(Ordering::Relaxed) >= self.state.limits.max_in_flight {
                    metrics.op(op_name, "busy", None);
                    return self.out.text(dtp_protocol::dtp_err(
                        &req_id,
                        "busy",
                        "too many requests in flight",
                    ));
                }
                self.spawn_op(req_id, op, params);
            }
            other => {
                metrics.op(other, "invalid", None);
                self.out.text(dtp_protocol::dtp_err(
                    &req_id,
                    "invalid",
                    &format!("unknown op {other}"),
                ));
            }
        }
    }

    fn spawn_op(&mut self, req_id: Value, op: String, params: Map<String, Value>) {
        let key = req_id.to_string();
        let flag = Arc::new(AtomicBool::new(false));
        self.cancels
            .lock()
            .unwrap()
            .insert(key.clone(), flag.clone());
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.state.metrics.in_flight.fetch_add(1, Ordering::Relaxed);
        let state = self.state.clone();
        let out = self.out.clone();
        let in_flight = self.in_flight.clone();
        let cancels = self.cancels.clone();
        let defaults = self.defaults.lock().unwrap().clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let graph = state.graph.load_full();
            let worker_state = state.clone();
            let op_name = op.clone();
            let result = tokio::task::spawn_blocking(move || {
                execute(&worker_state, &graph, &op_name, &params, &defaults)
            })
            .await
            .unwrap_or_else(|_| {
                Err(OpError {
                    code: "error",
                    message: "operation failed".into(),
                })
            });
            let cancelled = flag.load(Ordering::Relaxed);
            cancels.lock().unwrap().remove(&key);
            if !cancelled {
                match result {
                    Ok(value) => {
                        state
                            .metrics
                            .op(&op, "ok", Some(started.elapsed().as_secs_f64()));
                        out.text(dtp_protocol::dtp_ok(&req_id, &value));
                    }
                    Err(e) => {
                        let result = if e.code == "invalid" {
                            "invalid"
                        } else {
                            "error"
                        };
                        state.metrics.op(&op, result, None);
                        out.text(dtp_protocol::dtp_err(&req_id, e.code, &e.message));
                    }
                }
            }
            in_flight.fetch_sub(1, Ordering::Relaxed);
            state.metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
