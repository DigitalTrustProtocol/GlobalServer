//! `dtp-sync [--config dtp-sync.toml]`: runs the Sync Server until Ctrl-C.
//! The writer key comes from `DTP_SYNC_KEY`, `key_file`, or
//! `<data_dir>/sync.key` (generated on first start); add its pubkey to each
//! target with `dtp-global members add <pubkey> write`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};

use dtp_model::Keys;
use dtp_sync_server::{SyncConfig, start};

fn load_keys(cfg: &SyncConfig) -> anyhow::Result<Keys> {
    if let Ok(hex) = std::env::var("DTP_SYNC_KEY") {
        return Keys::from_secret_hex(&hex).context("DTP_SYNC_KEY is not a valid key");
    }
    let path = cfg
        .key_file
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&cfg.data_dir).join("sync.key"));
    if path.exists() {
        return Keys::from_secret_hex(&std::fs::read_to_string(&path)?).context("invalid key file");
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let keys = Keys::generate();
    std::fs::write(&path, keys.secret_hex())?;
    Ok(keys)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--print-config") {
        print!("{}", toml::to_string_pretty(&SyncConfig::default())?);
        return Ok(());
    }
    let cfg: SyncConfig = match args.iter().position(|a| a == "--config") {
        Some(i) => {
            let Some(p) = args.get(i + 1) else {
                bail!("--config needs a path")
            };
            toml::from_str(&std::fs::read_to_string(p).with_context(|| format!("read {p}"))?)?
        }
        None if Path::new("dtp-sync.toml").exists() => {
            toml::from_str(&std::fs::read_to_string("dtp-sync.toml")?)?
        }
        None => SyncConfig::default(),
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let keys = load_keys(&cfg)?;
    println!(
        "dtp-sync writer pubkey {} (grant it: dtp-global members add {} write)",
        keys.pubkey(),
        keys.pubkey()
    );
    let handle = start(cfg, keys);
    let stats = handle.stats.clone();
    let mut report = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = report.tick() => {
                use std::sync::atomic::Ordering::Relaxed;
                tracing::info!(
                    received = stats.received.load(Relaxed),
                    forwarded = stats.forwarded.load(Relaxed),
                    invalid = stats.dropped_invalid.load(Relaxed),
                    duplicate = stats.dropped_duplicate.load(Relaxed),
                    "sync progress"
                );
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    handle.shutdown().await;
    Ok(())
}
