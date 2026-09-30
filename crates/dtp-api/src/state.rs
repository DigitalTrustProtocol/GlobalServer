//! Shared server state.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc, watch};

use dtp_graph::Graph;
use dtp_model::{Event, Keys, ScopeProfile};
use dtp_protocol::Membership;
use dtp_resolve::Limits;
use dtp_store::{EventStore, WriteOp};

use crate::config::Config;
use crate::metrics::{Metrics, now_f64};
use crate::writer::WriterMsg;

/// One epoch's change summary for `graph` pushes.
#[derive(Clone, Debug)]
pub struct GraphChange {
    pub version: u64,
    pub subjects: Vec<String>,
}

pub struct AppState {
    pub config: Config,
    pub limits: Limits,
    pub profile: ScopeProfile,
    pub graph: ArcSwap<Graph>,
    pub store: Arc<dyn EventStore>,
    pub ingest_tx: mpsc::Sender<WriterMsg>,
    pub keys: Keys,
    /// Set to `true` on shutdown: connections and background tasks stop.
    pub shutdown: watch::Sender<bool>,
    membership: RwLock<(Membership, Vec<Event>)>,
    pub metrics: Metrics,
    pub ready: AtomicBool,
    pub ready_since: Mutex<f64>,
    pub instance_id: String,
    pub started_at: f64,
    pub pushes: broadcast::Sender<Arc<GraphChange>>,
    pub active_roots: Mutex<HashMap<String, f64>>,
    pub next_conn: AtomicU64,
    pub writer_conns: Mutex<HashMap<String, usize>>,
    pub ip_conns: Mutex<HashMap<IpAddr, usize>>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        graph: Graph,
        store: Arc<dyn EventStore>,
        ingest_tx: mpsc::Sender<WriterMsg>,
        keys: Keys,
        membership: Membership,
        instance_id: String,
    ) -> AppState {
        let limits = config.limits(&config.ingest);
        let profile = ScopeProfile::parse(&config.model.scope_profile).unwrap_or_default();
        let events = membership.sign(&keys, now_f64() as u64);
        let (pushes, _) = broadcast::channel(256);
        AppState {
            limits,
            profile,
            graph: ArcSwap::from_pointee(graph),
            store,
            ingest_tx,
            keys,
            shutdown: watch::channel(false).0,
            membership: RwLock::new((membership, events)),
            metrics: Metrics::default(),
            ready: AtomicBool::new(false),
            ready_since: Mutex::new(now_f64()),
            instance_id,
            started_at: now_f64(),
            pushes,
            active_roots: Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            writer_conns: Mutex::new(HashMap::new()),
            ip_conns: Mutex::new(HashMap::new()),
            config,
        }
    }

    pub fn membership(&self) -> Membership {
        self.membership.read().unwrap().0.clone()
    }

    /// Signed kind 13534 + 33534 events.
    pub fn membership_events(&self) -> Vec<Event> {
        self.membership.read().unwrap().1.clone()
    }

    /// Replaces the member list, re-signs it, and persists it.
    pub fn set_membership(&self, membership: Membership) -> anyhow::Result<()> {
        let events = membership.sign(&self.keys, now_f64() as u64);
        self.store.write(&[WriteOp::Meta {
            name: "members".into(),
            value: membership.to_json().to_string().into_bytes(),
        }])?;
        *self.membership.write().unwrap() = (membership, events);
        Ok(())
    }

    /// Whether `pubkeys` may perform a request class under `role`.
    pub fn allowed(
        &self,
        access: &crate::config::Access,
        pubkeys: &[String],
        role: &str,
    ) -> Result<(), String> {
        if *access == crate::config::Access::Open {
            return Ok(());
        }
        if pubkeys.is_empty() {
            return Err(format!(
                "auth-required: this server requires authentication for {role}s"
            ));
        }
        let m = self.membership.read().unwrap();
        let is_admin = |pk: &String| self.config.auth.admins.iter().any(|a| a == pk);
        if pubkeys
            .iter()
            .any(|pk| m.0.has_role(pk, role) || is_admin(pk))
        {
            Ok(())
        } else {
            Err(format!("restricted: not a member with role {role}"))
        }
    }

    pub fn server_now(&self) -> u64 {
        now_f64() as u64
    }

    pub fn touch_root(&self, root: &str) {
        let mut roots = self.active_roots.lock().unwrap();
        roots.insert(root.to_string(), now_f64());
        let cutoff = now_f64() - 30.0 * 86_400.0;
        roots.retain(|_, t| *t >= cutoff);
    }

    /// The NIP-11 `dtp` object.
    pub fn dtp_info(&self) -> Value {
        json!({
            "api": dtp_model::API_VERSION,
            "model": dtp_model::MODEL_VERSION,
            "corpus": dtp_model::CORPUS_VERSION,
            "instanceId": self.instance_id,
            "scopeProfile": self.profile.name(),
            "capabilities": dtp_protocol::CAPABILITIES,
            "limits": self.limits.to_json(),
        })
    }

    /// The NIP-11 document.
    pub fn nip11(&self) -> Value {
        use crate::config::Access;
        json!({
            "name": self.config.server.instance_name,
            "description": self.config.server.description,
            "pubkey": self.config.auth.admins.first(),
            "self": self.keys.pubkey(),
            "software": "https://github.com/DigitalTrustProtocol/GlobalServer",
            "version": env!("CARGO_PKG_VERSION"),
            "supported_nips": [1, 9, 11, 42, 43],
            "limitation": {
                "max_message_length": self.limits.max_message_length,
                "auth_required": self.config.auth.reads == Access::Members,
                "restricted_writes": self.config.auth.writes == Access::Members,
                "max_subscriptions": 20,
                "max_limit": 500,
            },
            "dtp": self.dtp_info(),
        })
    }
}
