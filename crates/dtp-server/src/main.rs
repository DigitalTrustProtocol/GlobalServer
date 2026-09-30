//! `dtp-global`: the Global Server resolver.
//!
//! ```text
//! dtp-global [--config dtp-global.toml]                 serve
//! dtp-global [--config …] members list
//! dtp-global [--config …] members add <pubkey> <read|write|admin>
//! dtp-global [--config …] members remove <pubkey> [role]
//! dtp-global [--config …] key                           print the server pubkey (NIP-11 `self`)
//! dtp-global --print-config                             print the default configuration
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};

use dtp_api::Config;
use dtp_model::Keys;
use dtp_protocol::Membership;
use dtp_store::{EventStore, RedbStore, WriteOp};

fn load_config(path: Option<&Path>) -> anyhow::Result<Config> {
    match path {
        Some(p) => {
            let text =
                std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
            toml::from_str(&text).with_context(|| format!("parse {}", p.display()))
        }
        None => {
            let default = Path::new("dtp-global.toml");
            if default.exists() {
                load_config(Some(default))
            } else {
                Ok(Config::default())
            }
        }
    }
}

/// Server key: `DTP_SERVER_KEY` (hex), else `server.key_file`, else
/// `<data_dir>/server.key` (generated on first start). Never from the TOML.
fn load_keys(config: &Config) -> anyhow::Result<Keys> {
    if let Ok(hex) = std::env::var("DTP_SERVER_KEY") {
        return Keys::from_secret_hex(&hex)
            .context("DTP_SERVER_KEY is not a valid 64-hex secret key");
    }
    let path = config
        .server
        .key_file
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&config.storage.data_dir).join("server.key"));
    if path.exists() {
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        return Keys::from_secret_hex(&text)
            .with_context(|| format!("{} is not a valid key", path.display()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let keys = Keys::generate();
    std::fs::write(&path, keys.secret_hex())?;
    eprintln!(
        "generated server key {} (pubkey {})",
        path.display(),
        keys.pubkey()
    );
    Ok(keys)
}

fn open_store(config: &Config) -> anyhow::Result<RedbStore> {
    let dir = Path::new(&config.storage.data_dir);
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(RedbStore::open(&dir.join("events.redb"))?)
}

fn members(config: &Config, args: &[String]) -> anyhow::Result<()> {
    let store = open_store(config)?;
    let mut m = dtp_api::load_membership(&store, config)?;
    match args.first().map(String::as_str) {
        Some("list") | None => {}
        Some("add") => {
            let (Some(pk), Some(role)) = (args.get(1), args.get(2)) else {
                bail!("usage: members add <pubkey> <read|write|admin>");
            };
            let pk = normalize_pubkey(pk)?;
            if !m.add(&pk, role) && !m.has_role(&pk, role) {
                bail!("role must be read, write, or admin");
            }
        }
        Some("remove") => {
            let Some(pk) = args.get(1) else {
                bail!("usage: members remove <pubkey> [role]");
            };
            m.remove(&normalize_pubkey(pk)?, args.get(2).map(String::as_str));
        }
        Some(other) => bail!("unknown members command {other}"),
    }
    store.write(&[WriteOp::Meta {
        name: "members".into(),
        value: m.to_json().to_string().into_bytes(),
    }])?;
    print_members(&m);
    Ok(())
}

fn normalize_pubkey(pk: &str) -> anyhow::Result<String> {
    if let Some(hex) = dtp_model::decode_npub(pk) {
        return Ok(hex);
    }
    let lower = pk.to_ascii_lowercase();
    if dtp_model::is_hex64(&lower) {
        Ok(lower)
    } else {
        bail!("{pk} is neither 64-hex nor npub")
    }
}

fn print_members(m: &Membership) {
    for (pk, roles) in &m.members {
        println!(
            "{pk} {}",
            roles.iter().cloned().collect::<Vec<_>>().join(",")
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path: Option<PathBuf> = None;
    if let Some(i) = args.iter().position(|a| a == "--config") {
        let Some(p) = args.get(i + 1).cloned() else {
            bail!("--config needs a path");
        };
        config_path = Some(PathBuf::from(p));
        args.drain(i..=i + 1);
    }
    if args.first().map(String::as_str) == Some("--print-config") {
        print!("{}", toml::to_string_pretty(&Config::default())?);
        return Ok(());
    }
    let config = load_config(config_path.as_deref())?;
    match args.first().map(String::as_str) {
        Some("members") => return members(&config, &args[1..]),
        Some("key") => {
            println!("{}", load_keys(&config)?.pubkey());
            return Ok(());
        }
        Some(other) if other != "serve" => bail!("unknown command {other}"),
        _ => {}
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let keys = load_keys(&config)?;
    let store = open_store(&config)?;
    let handle = dtp_api::start(config, Arc::new(store), keys).await?;
    println!(
        "dtp-global listening on ws://{} (admin http://{})",
        handle.addr, handle.admin_addr
    );
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            handle.shutdown().await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips_through_toml() {
        let text = toml::to_string_pretty(&Config::default()).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.server.listen, "127.0.0.1:3880");
        assert_eq!(back.auth.writes, dtp_api::config::Access::Members);
        assert_eq!(back.guardrails.max_depth, 6);
    }

    #[test]
    fn partial_config_and_unimplemented_sections() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            listen = "0.0.0.0:4000"
            [auth]
            reads = "members"
            members = [{ pubkey = "abababababababababababababababababababababababababababababababab", roles = ["write"] }]
            [retention]
            d_reach = 6
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.listen, "0.0.0.0:4000");
        assert_eq!(cfg.auth.reads, dtp_api::config::Access::Members);
        assert_eq!(cfg.auth.members.len(), 1);
        assert!(cfg.retention.is_some());
        assert_eq!(cfg.guardrails.operation_deadline_ms, 250);
    }

    #[test]
    fn key_file_is_generated_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.storage.data_dir = dir.path().display().to_string();
        let a = load_keys(&cfg).unwrap();
        let b = load_keys(&cfg).unwrap();
        assert_eq!(a.pubkey(), b.pubkey());
    }
}
