//! Admin listener (TrustGraph telemetry.md): `/admin/api/telemetry`
//! (schema `dtp-telemetry/1`), `/admin/api/stream` (SSE), `/metrics`, and a
//! placeholder page until `@dtp/telemetry-ui` is embedded.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use futures_util::Stream;
use serde_json::{Value, json};

use crate::metrics::now_f64;
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/admin/api/telemetry", get(telemetry))
        .route("/admin/api/stream", get(stream))
        .route("/admin/api/history", get(history))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn page() -> Html<&'static str> {
    Html(concat!(
        "<!doctype html><html><head><meta charset=utf-8><title>dtp-global telemetry</title>",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"></head><body>",
        "<h1>dtp-global</h1><p>The shared telemetry UI (<code>@dtp/telemetry-ui</code>) is not embedded yet.</p>",
        "<ul><li><a href=\"/admin/api/telemetry\">/admin/api/telemetry</a> (JSON snapshot)</li>",
        "<li><a href=\"/admin/api/stream\">/admin/api/stream</a> (Server-Sent Events)</li>",
        "<li><a href=\"/metrics\">/metrics</a> (Prometheus)</li></ul></body></html>"
    ))
}

fn rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .nth(1)
                .and_then(|p| p.parse::<u64>().ok())
        })
        .map_or(0, |pages| pages * 4096)
}

/// The `dtp-telemetry/1` snapshot.
pub fn snapshot(state: &AppState) -> Value {
    let graph = state.graph.load();
    let stats = graph.stats();
    let ready = state.ready.load(Ordering::Relaxed);
    let now = now_f64();
    let (eps, by_kind, prefixes) = state.metrics.ingest_json();
    let total_bytes = (stats.hot_bytes + stats.cold_bytes + stats.core_bytes) as f64;
    let edges = (stats.trust_edges + stats.rating_edges) as f64;
    let membership = state.membership();
    let queue_depth = state.metrics.queue_depth.load(Ordering::Relaxed);
    let roots = state.active_roots.lock().unwrap().len();
    let mut effective = serde_json::to_value(&state.config).unwrap_or(Value::Null);
    effective["server"]["key_file"] =
        json!(state.config.server.key_file.as_ref().map(|_| "<redacted>"));
    let unsupported: Vec<&str> = [
        ("retention", state.config.retention.is_some()),
        ("memory", state.config.memory.is_some()),
        ("residency", state.config.residency.is_some()),
        ("limits", state.config.limits.is_some()),
    ]
    .iter()
    .filter(|(_, set)| *set)
    .map(|(n, _)| *n)
    .collect();
    effective["notImplemented"] = json!(unsupported);
    let not_ready = !ready;
    json!({
        "schema": "dtp-telemetry/1",
        "generatedAt": now,
        "server": {
            "kind": "global",
            "version": env!("CARGO_PKG_VERSION"),
            "api": dtp_model::API_VERSION,
            "model": dtp_model::MODEL_VERSION,
            "corpus": dtp_model::CORPUS_VERSION,
            "instanceId": state.instance_id,
            "startedAt": state.started_at,
            "uptimeSeconds": now - state.started_at,
        },
        "health": {
            "ready": ready,
            "stateSinceSeconds": now - *state.ready_since.lock().unwrap(),
            "notReadyReason": if ready { Value::Null } else { json!("replaying event store") },
        },
        "graph": {
            "graphVersion": graph.epoch(),
            "epochLagSeconds": null,
            "nodes": stats.nodes,
            "edges": { "32009": stats.trust_edges, "32014": stats.rating_edges },
            "claims": stats.claims,
            "hintedStatements": stats.hinted_statements,
            "deleteFloors": stats.delete_floors,
            "bytes": { "total": total_bytes, "resident": total_bytes, "pinned": null },
            "bytesPerEdge": if edges > 0.0 { json!(total_bytes / edges) } else { Value::Null },
            "impl": {
                "hotBytes": stats.hot_bytes,
                "coldBytes": stats.cold_bytes,
                "coreBytes": stats.core_bytes,
                "deltaEntries": graph.delta_entries(),
                "deadEdges": stats.dead_edges,
                "segments": 1,
            },
        },
        "ingest": {
            "eventsPerSecond": eps,
            "byKind": by_kind,
            "rejectsByPrefix": prefixes,
            "deletions": state.metrics.deletions.load(Ordering::Relaxed),
            "queueDepth": queue_depth,
            "queueCap": state.config.ingest.queue_size,
            "pendingOks": state.metrics.pending_oks.load(Ordering::Relaxed),
            "writers": state.metrics.writers_json(),
        },
        "sources": {
            "relays": null,
            "frontier": null,
            "writers": state.metrics.writers_json(),
            "wantsOpen": 0,
        },
        "queries": state.metrics.queries_json(),
        "connections": state.metrics.connections_json(),
        "memory": {
            "limitBytes": null,
            "rssBytes": rss_bytes(),
            "shares": {
                "core": { "bytes": stats.core_bytes, "limit": null },
                "hot": { "bytes": stats.hot_bytes, "limit": null },
                "cold": { "bytes": stats.cold_bytes, "limit": null },
            },
            "watchdog": "ok",
            "impl": {},
        },
        "roots": { "active": roots, "warming": 0, "coveragePushes": 0 },
        "logs": state.metrics.logs_json(),
        "config": {
            "effective": effective,
            "nip11": state.nip11(),
            "membership": { "counts": membership.counts(), "members": membership.to_json() },
        },
        "alerts": [
            { "name": "not-ready", "active": not_ready, "since": if not_ready { json!(state.started_at) } else { Value::Null } },
            { "name": "memory-pressure", "active": false, "since": null },
            { "name": "ingest-backlog", "active": queue_depth * 2 > state.config.ingest.queue_size, "since": null },
            { "name": "guardrail-storm", "active": false, "since": null },
            { "name": "source-down", "active": false, "since": null },
            { "name": "slow-queries", "active": false, "since": null },
        ],
    })
}

async fn telemetry(State(state): State<Arc<AppState>>) -> axum::Json<Value> {
    axum::Json(snapshot(&state))
}

async fn stream(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let s = futures_util::stream::unfold((state, true), |(state, first)| async move {
        if !first {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let event = SseEvent::default()
            .event("snapshot")
            .data(snapshot(&state).to_string());
        Some((Ok(event), (state, false)))
    });
    Sse::new(s).keep_alive(KeepAlive::default())
}

async fn history() -> Response {
    let body = json!({ "error": "unsupported: history ring buffers are not implemented yet" });
    (StatusCode::NOT_IMPLEMENTED, axum::Json(body)).into_response()
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    use std::fmt::Write;
    let graph = state.graph.load();
    let stats = graph.stats();
    let mut out = String::new();
    let ready = u8::from(state.ready.load(Ordering::Relaxed));
    let _ = writeln!(out, "# TYPE dtp_up gauge\ndtp_up 1");
    let _ = writeln!(out, "# TYPE dtp_ready gauge\ndtp_ready {ready}");
    let _ = writeln!(
        out,
        "# TYPE dtp_graph_version gauge\ndtp_graph_version {}",
        graph.epoch()
    );
    let _ = writeln!(
        out,
        "# TYPE dtp_epoch_lag_seconds gauge\ndtp_epoch_lag_seconds 0"
    );
    let _ = writeln!(
        out,
        "# TYPE dtp_graph_nodes gauge\ndtp_graph_nodes {}",
        stats.nodes
    );
    let _ = writeln!(out, "# TYPE dtp_graph_edges gauge");
    let _ = writeln!(
        out,
        "dtp_graph_edges{{kind=\"32009\"}} {}",
        stats.trust_edges
    );
    let _ = writeln!(
        out,
        "dtp_graph_edges{{kind=\"32014\"}} {}",
        stats.rating_edges
    );
    let total = stats.hot_bytes + stats.cold_bytes + stats.core_bytes;
    let _ = writeln!(out, "# TYPE dtp_graph_bytes gauge");
    let _ = writeln!(out, "dtp_graph_bytes{{tier=\"total\"}} {total}");
    let _ = writeln!(out, "dtp_graph_bytes{{tier=\"resident\"}} {total}");
    let _ = writeln!(out, "dtp_graph_bytes{{tier=\"pinned\"}} 0");
    let _ = writeln!(out, "# TYPE dtp_want_open gauge\ndtp_want_open 0");
    let _ = writeln!(
        out,
        "# TYPE dtp_background_completions_total counter\ndtp_background_completions_total 0"
    );
    let _ = writeln!(
        out,
        "# TYPE dtp_field_cache_hits_total counter\ndtp_field_cache_hits_total 0"
    );
    let _ = writeln!(
        out,
        "# TYPE dtp_field_cache_misses_total counter\ndtp_field_cache_misses_total 0"
    );
    let _ = writeln!(
        out,
        "# TYPE dtp_field_cache_bytes gauge\ndtp_field_cache_bytes 0"
    );
    let _ = writeln!(out, "# TYPE dtp_memory_bytes gauge");
    let _ = writeln!(
        out,
        "dtp_memory_bytes{{share=\"core\"}} {}",
        stats.core_bytes
    );
    let _ = writeln!(out, "dtp_memory_bytes{{share=\"hot\"}} {}", stats.hot_bytes);
    let _ = writeln!(
        out,
        "dtp_memory_bytes{{share=\"cold\"}} {}",
        stats.cold_bytes
    );
    let _ = writeln!(
        out,
        "# TYPE dtp_rss_bytes gauge\ndtp_rss_bytes {}",
        rss_bytes()
    );
    let roots = state.active_roots.lock().unwrap().len();
    let _ = writeln!(out, "# TYPE dtp_roots gauge");
    let _ = writeln!(out, "dtp_roots{{state=\"active\"}} {roots}");
    let _ = writeln!(out, "dtp_roots{{state=\"warming\"}} 0");
    let _ = writeln!(out, "# TYPE dtp_alert gauge");
    let _ = writeln!(out, "dtp_alert{{name=\"not-ready\"}} {}", 1 - ready);
    state.metrics.prometheus(&mut out);
    let _ = writeln!(out, "# TYPE dtp_impl_segments gauge\ndtp_impl_segments 1");
    let _ = writeln!(
        out,
        "# TYPE dtp_impl_delta_entries gauge\ndtp_impl_delta_entries {}",
        graph.delta_entries()
    );
    let _ = writeln!(
        out,
        "# TYPE dtp_impl_dead_edges gauge\ndtp_impl_dead_edges {}",
        stats.dead_edges
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out).into_response()
}
