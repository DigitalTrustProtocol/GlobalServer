//! `dtp-api`: the resolver's network surface (TrustGraph resolver-api.md).
//!
//! One WebSocket per server (NIP-01 framing): `EVENT` ingest with `OK`
//! prefixes and TCP backpressure, NIP-42 `AUTH` with `auth.reads` /
//! `auth.writes`, the NIP-43 membership list, limited `REQ`, and every `DTP`
//! operation of protocol v1. HTTP serves NIP-11, `/healthz`, `/readyz`; the
//! admin listener serves telemetry and `/metrics`.

pub mod admin;
pub mod config;
pub mod http;
pub mod metrics;
pub mod ops;
pub mod state;
pub mod writer;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Context;
use rand::RngCore;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use dtp_model::Keys;
use dtp_protocol::Membership;
use dtp_store::EventStore;

pub use config::Config;
pub use state::AppState;

/// A running server.
pub struct ServerHandle {
    pub addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub state: Arc<AppState>,
    shutdown: Option<oneshot::Sender<()>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    writer: Option<std::thread::JoinHandle<()>>,
}

impl ServerHandle {
    /// Stops the listeners, closes every connection, drains the writer, and
    /// releases the event store before returning.
    pub async fn shutdown(mut self) {
        let _ = self.state.shutdown.send(true);
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        for t in self.tasks.drain(..) {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), t).await;
        }
        let _ = self.state.ingest_tx.send(writer::WriterMsg::Stop).await;
        if let Some(w) = self.writer.take() {
            let _ = tokio::task::spawn_blocking(move || w.join()).await;
        }
        for _ in 0..100 {
            if Arc::strong_count(&self.state) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Waits until the protocol listener stops.
    pub async fn wait(mut self) {
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
    }
}

/// Loads the member list: the stored NIP-43 list merged with config members.
pub fn load_membership(store: &dyn EventStore, config: &Config) -> anyhow::Result<Membership> {
    let mut membership = match store.meta("members")? {
        Some(bytes) => Membership::from_json(&serde_json::from_slice(&bytes).unwrap_or_default()),
        None => Membership::default(),
    };
    for m in &config.auth.members {
        for role in &m.roles {
            if !membership.add(&m.pubkey.to_ascii_lowercase(), role)
                && !membership.has_role(&m.pubkey, role)
            {
                anyhow::bail!("invalid member {} / role {role}", m.pubkey);
            }
        }
    }
    Ok(membership)
}

/// Replays the store, binds both listeners, and starts serving.
pub async fn start(
    config: Config,
    store: Arc<dyn EventStore>,
    keys: Keys,
) -> anyhow::Result<ServerHandle> {
    let profile = dtp_model::ScopeProfile::parse(&config.model.scope_profile)
        .with_context(|| format!("unknown scope profile {}", config.model.scope_profile))?;
    let membership = load_membership(store.as_ref(), &config)?;
    let (graph, replayed) = writer::replay(store.as_ref(), profile)?;
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let (ingest_tx, ingest_rx) = mpsc::channel(config.ingest.queue_size.max(1));
    let listener = TcpListener::bind(&config.server.listen)
        .await
        .with_context(|| format!("bind {}", config.server.listen))?;
    let addr = listener.local_addr()?;
    let admin_listen = config.admin.listen.clone().unwrap_or_else(|| {
        let port = if addr.port() == 0 {
            0
        } else {
            addr.port().saturating_add(1)
        };
        format!("127.0.0.1:{port}")
    });
    let admin_listener = TcpListener::bind(&admin_listen)
        .await
        .with_context(|| format!("bind admin {admin_listen}"))?;
    let admin_addr = admin_listener.local_addr()?;
    let state = Arc::new(AppState::new(
        config,
        graph,
        store,
        ingest_tx,
        keys,
        membership.clone(),
        hex::encode(id),
    ));
    state.set_membership(membership)?;
    let writer_state = state.clone();
    let writer = std::thread::Builder::new()
        .name("dtp-graph-writer".into())
        .spawn(move || writer::run_writer(writer_state, ingest_rx))?;
    tracing::info!(replayed, %addr, %admin_addr, "dtp-global serving");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (admin_stop_tx, admin_stop_rx) = oneshot::channel::<()>();
    let app = http::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let main = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
                let _ = admin_stop_tx.send(());
            })
            .await;
    });
    let admin_app = admin::router(state.clone());
    let admin = tokio::spawn(async move {
        let _ = axum::serve(admin_listener, admin_app)
            .with_graceful_shutdown(async move {
                let _ = admin_stop_rx.await;
            })
            .await;
    });
    let sampler_state = state.clone();
    let mut stop = state.shutdown.subscribe();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tokio::select! {
                _ = tick.tick() => sampler_state.metrics.sample_rates(),
                _ = stop.changed() => break,
            }
        }
    });
    state.ready.store(true, Ordering::Relaxed);
    *state.ready_since.lock().unwrap() = metrics::now_f64();
    Ok(ServerHandle {
        addr,
        admin_addr,
        state,
        shutdown: Some(shutdown_tx),
        tasks: vec![main, admin],
        writer: Some(writer),
    })
}
