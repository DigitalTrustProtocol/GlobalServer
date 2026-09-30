//! `dtp-sync`: the reference writer (specs/sync-server.md).
//!
//! Crawls relays for kinds `32009`, `32014`, `10011` and the NIP-09 kind `5`
//! deletions that target them (`until`-paginated backfill, then a live
//! subscription from `now − overlap`), drops junk before it costs a resolver
//! anything (kind allowlist, duplicate ids, id hash and signature), and pushes
//! the rest into every target resolver over one NIP-42-authenticated
//! connection each, reconnecting with backoff.
//!
//! Not built yet (see PLAN.md): durable relay cursors and per-target
//! positions, NIP-77 negentropy, `want` demand answers, NIP-11 limits, and the
//! admin telemetry pages.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use dtp_model::{Event, Keys};
use dtp_relay::{PushStats, Pusher};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    pub relays: Vec<String>,
    pub targets: Vec<String>,
    /// File with the writer's secret key (hex). `DTP_SYNC_KEY` overrides.
    pub key_file: Option<String>,
    pub data_dir: String,
    pub backfill: BackfillCfg,
    pub live: LiveCfg,
}

impl Default for SyncConfig {
    fn default() -> Self {
        SyncConfig {
            relays: Vec::new(),
            targets: vec!["ws://127.0.0.1:3880/".into()],
            key_file: None,
            data_dir: "data-sync".into(),
            backfill: BackfillCfg::default(),
            live: LiveCfg::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct BackfillCfg {
    pub enabled: bool,
    /// Oldest `created_at` to fetch (none: everything the relay returns).
    pub since: Option<u64>,
    pub page: usize,
    pub max_pages: usize,
}

impl Default for BackfillCfg {
    fn default() -> Self {
        BackfillCfg {
            enabled: true,
            since: None,
            page: 500,
            max_pages: 200,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LiveCfg {
    pub enabled: bool,
    pub overlap_seconds: u64,
}

impl Default for LiveCfg {
    fn default() -> Self {
        LiveCfg {
            enabled: true,
            overlap_seconds: 600,
        }
    }
}

/// Counters shared by the tasks.
#[derive(Default)]
pub struct SyncStats {
    pub received: AtomicU64,
    pub dropped_invalid: AtomicU64,
    pub dropped_duplicate: AtomicU64,
    pub forwarded: AtomicU64,
    pub relay_errors: AtomicU64,
    pub targets: Mutex<Vec<(String, PushStats)>>,
}

impl SyncStats {
    pub fn target(&self, url: &str) -> PushStats {
        self.targets
            .lock()
            .unwrap()
            .iter()
            .find(|(u, _)| u == url)
            .map(|(_, s)| s.clone())
            .unwrap_or_default()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pre-filter: held kinds only, valid id and signature.
pub fn prefilter(event: &Event) -> bool {
    dtp_protocol::is_ingest_kind(event.kind) && event.verify().is_ok()
}

async fn backoff_sleep(attempt: &mut u32, stop: &mut watch::Receiver<bool>) -> bool {
    let ms = (500u64 << (*attempt).min(6)).min(30_000);
    *attempt += 1;
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(ms)) => true,
        _ = stop.changed() => false,
    }
}

async fn relay_task(
    url: String,
    cfg: SyncConfig,
    tx: mpsc::Sender<Event>,
    stats: Arc<SyncStats>,
    mut stop: watch::Receiver<bool>,
) {
    let started = now();
    if cfg.backfill.enabled {
        match dtp_relay::backfill(
            &url,
            cfg.backfill.since,
            cfg.backfill.page,
            cfg.backfill.max_pages,
            Duration::from_secs(30),
        )
        .await
        {
            Ok(events) => {
                tracing::info!(relay = %url, events = events.len(), "backfill done");
                for e in events {
                    if tx.send(e).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                stats.relay_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(relay = %url, "backfill failed: {e}");
            }
        }
    }
    if !cfg.live.enabled {
        return;
    }
    let mut attempt = 0;
    loop {
        let since = started.saturating_sub(cfg.live.overlap_seconds);
        tokio::select! {
            result = dtp_relay::live(&url, since, tx.clone()) => {
                if let Err(e) = result {
                    stats.relay_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(relay = %url, "live subscription ended: {e}");
                }
            }
            _ = stop.changed() => return,
        }
        if !backoff_sleep(&mut attempt, &mut stop).await {
            return;
        }
    }
}

async fn target_task(
    url: String,
    keys: Keys,
    mut rx: mpsc::Receiver<Event>,
    stats: Arc<SyncStats>,
    mut stop: watch::Receiver<bool>,
) {
    let mut attempt = 0;
    let mut batch: Vec<Event> = Vec::new();
    loop {
        let mut pusher = match Pusher::connect(&url, &keys).await {
            Ok(p) => {
                attempt = 0;
                p
            }
            Err(e) => {
                tracing::warn!(target = %url, "connect failed: {e}");
                if !backoff_sleep(&mut attempt, &mut stop).await {
                    return;
                }
                continue;
            }
        };
        loop {
            if batch.is_empty() {
                tokio::select! {
                    next = rx.recv() => match next {
                        Some(e) => batch.push(e),
                        None => return,
                    },
                    _ = stop.changed() => return,
                }
                while batch.len() < 500 {
                    match rx.try_recv() {
                        Ok(e) => batch.push(e),
                        Err(_) => break,
                    }
                }
            }
            match pusher.push(&batch).await {
                Ok(answers) => {
                    let mut all = stats.targets.lock().unwrap();
                    let entry = match all.iter().position(|(u, _)| *u == url) {
                        Some(i) => &mut all[i].1,
                        None => {
                            all.push((url.clone(), PushStats::default()));
                            &mut all.last_mut().unwrap().1
                        }
                    };
                    for (_, ok, msg) in &answers {
                        entry.record(*ok, msg);
                    }
                    batch.clear();
                }
                Err(e) => {
                    tracing::warn!(target = %url, "push failed, reconnecting: {e}");
                    break;
                }
            }
        }
        if !backoff_sleep(&mut attempt, &mut stop).await {
            return;
        }
    }
}

/// A running Sync Server.
pub struct SyncHandle {
    pub stats: Arc<SyncStats>,
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SyncHandle {
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
    }
}

/// Starts relay, dispatch, and target tasks.
pub fn start(cfg: SyncConfig, keys: Keys) -> SyncHandle {
    let stats = Arc::new(SyncStats::default());
    let (stop, stop_rx) = watch::channel(false);
    let (in_tx, mut in_rx) = mpsc::channel::<Event>(10_000);
    let mut tasks = Vec::new();
    let mut target_txs = Vec::new();
    for url in &cfg.targets {
        let (tx, rx) = mpsc::channel::<Event>(10_000);
        target_txs.push(tx);
        tasks.push(tokio::spawn(target_task(
            url.clone(),
            keys.clone(),
            rx,
            stats.clone(),
            stop_rx.clone(),
        )));
    }
    let dispatch_stats = stats.clone();
    let mut dispatch_stop = stop_rx.clone();
    tasks.push(tokio::spawn(async move {
        let mut seen: HashSet<String> = HashSet::new();
        loop {
            let event = tokio::select! {
                e = in_rx.recv() => match e { Some(e) => e, None => return },
                _ = dispatch_stop.changed() => return,
            };
            dispatch_stats.received.fetch_add(1, Ordering::Relaxed);
            if seen.len() > 1_000_000 {
                seen.clear();
            }
            if !seen.insert(event.id.clone()) {
                dispatch_stats
                    .dropped_duplicate
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if !prefilter(&event) {
                dispatch_stats
                    .dropped_invalid
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            dispatch_stats.forwarded.fetch_add(1, Ordering::Relaxed);
            for tx in &target_txs {
                let _ = tx.send(event.clone()).await;
            }
        }
    }));
    for url in &cfg.relays {
        tasks.push(tokio::spawn(relay_task(
            url.clone(),
            cfg.clone(),
            in_tx.clone(),
            stats.clone(),
            stop_rx.clone(),
        )));
    }
    SyncHandle { stats, stop, tasks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_toml() {
        let cfg: SyncConfig =
            toml::from_str("relays = [\"wss://relay.example\"]\n[backfill]\nsince = 10\n").unwrap();
        assert_eq!(cfg.relays, vec!["wss://relay.example"]);
        assert_eq!(cfg.backfill.since, Some(10));
        assert_eq!(cfg.backfill.page, 500);
        assert!(cfg.live.enabled);
    }

    #[test]
    fn prefilter_drops_junk() {
        let keys = Keys::from_seed("a");
        assert!(!prefilter(&keys.sign_event(1, 1, vec![], "")));
        let mut ev = keys.sign_event(1, 32009, vec![], "");
        assert!(prefilter(&ev));
        ev.content = "x".into();
        assert!(!prefilter(&ev));
    }
}
