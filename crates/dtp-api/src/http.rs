//! Protocol listener routes: WebSocket upgrade and NIP-11 on `/`, NIP-86 on
//! `POST /` (not implemented: 501), `/healthz`, `/readyz`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Router;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use crate::state::AppState;
use crate::ws::{ConnInfo, handle_socket};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(root).post(nip86))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(state)
}

fn host_allowed(state: &AppState, host: Option<&str>) -> bool {
    let allowed = &state.config.server.allowed_hosts;
    if allowed.iter().any(|h| h == "*") {
        return true;
    }
    let Some(host) = host else { return false };
    let bare = host.rsplit_once(':').map_or(host, |(h, _)| h);
    allowed
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host) || h.eq_ignore_ascii_case(bare))
}

fn origin_allowed(state: &AppState, origin: Option<&str>) -> bool {
    let Some(origin) = origin else { return true };
    let allowed = &state.config.server.allowed_origins;
    allowed
        .iter()
        .any(|o| o == "*" || o.eq_ignore_ascii_case(origin))
}

fn origin_class(origin: Option<&str>) -> &'static str {
    match origin {
        None => "native",
        Some(o) if o.starts_with("chrome-extension://") || o.starts_with("moz-extension://") => {
            "extension"
        }
        Some(_) => "other",
    }
}

async fn root(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let ws = ws.ok();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !host_allowed(&state, host) {
        return (StatusCode::FORBIDDEN, "host not allowed").into_response();
    }
    if let Some(ws) = ws {
        if !origin_allowed(&state, origin) {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
        let ip = addr.ip();
        {
            let mut conns = state.ip_conns.lock().unwrap();
            let n = conns.entry(ip).or_default();
            if *n >= state.limits.max_connections {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate-limited: too many connections from this client",
                )
                    .into_response();
            }
            *n += 1;
        }
        let mut relay_urls: Vec<String> = state.config.server.public_url.iter().cloned().collect();
        if let Some(h) = host {
            relay_urls.push(format!("ws://{h}/"));
            relay_urls.push(format!("wss://{h}/"));
        }
        let info = ConnInfo {
            ip,
            origin_class: origin_class(origin),
            relay_urls,
        };
        let limit = state.limits.max_message_length;
        return ws.max_message_size(limit).max_frame_size(limit).on_upgrade(
            move |socket| async move {
                let ip = info.ip;
                handle_socket(socket, state.clone(), info).await;
                let mut conns = state.ip_conns.lock().unwrap();
                if let Some(n) = conns.get_mut(&ip) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        conns.remove(&ip);
                    }
                }
            },
        );
    }
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if accept.contains("application/nostr+json") {
        let mut response = axum::Json(state.nip11()).into_response();
        let h = response.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/nostr+json"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("*"),
        );
        return response;
    }
    (
        StatusCode::OK,
        "DTP Global Server. Connect with a WebSocket (resolver protocol v1) or GET with Accept: application/nostr+json.\n",
    )
        .into_response()
}

async fn nip86() -> Response {
    let body = json!({ "result": null, "error": "unsupported: NIP-86 management is not implemented yet; use the dtp-global members CLI" });
    (StatusCode::NOT_IMPLEMENTED, axum::Json(body)).into_response()
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    if state.ready.load(Ordering::Relaxed) {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
    }
}
