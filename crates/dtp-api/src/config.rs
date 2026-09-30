//! Resolver configuration (api-privacy-operations.md § Configuration).
//! Deserialized from `dtp-global.toml` by `dtp-server`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use dtp_resolve::Limits;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerCfg,
    pub model: ModelCfg,
    pub auth: AuthCfg,
    pub ingest: IngestCfg,
    pub guardrails: GuardrailsCfg,
    pub storage: StorageCfg,
    pub admin: AdminCfg,
    /// Accepted but not implemented yet (reported in the admin config page).
    pub retention: Option<Value>,
    pub memory: Option<Value>,
    pub residency: Option<Value>,
    pub limits: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerCfg {
    pub listen: String,
    /// Public WebSocket URL (NIP-42 `relay` tag); `ws://<Host>/` is also accepted.
    pub public_url: Option<String>,
    pub instance_name: String,
    pub description: String,
    /// File holding the server's secret key (hex). `DTP_SERVER_KEY` overrides.
    pub key_file: Option<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_hosts: Vec<String>,
}

impl Default for ServerCfg {
    fn default() -> Self {
        ServerCfg {
            listen: "127.0.0.1:3880".into(),
            public_url: None,
            instance_name: "dtp-global".into(),
            description: "DTP Global Server: Web-of-Trust resolver (kinds 32009, 32014, 10011)"
                .into(),
            key_file: None,
            allowed_origins: vec!["*".into()],
            allowed_hosts: vec!["*".into()],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelCfg {
    pub scope_profile: String,
    pub binding_mode: String,
    pub follow_trust_threshold: u64,
    pub follow_trust_red: u64,
}

impl Default for ModelCfg {
    fn default() -> Self {
        ModelCfg {
            scope_profile: "x.com".into(),
            binding_mode: "lenient".into(),
            follow_trust_threshold: 75,
            follow_trust_red: 25,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Open,
    Members,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberCfg {
    pub pubkey: String,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthCfg {
    pub reads: Access,
    pub writes: Access,
    pub admins: Vec<String>,
    pub membership_source: String,
    /// Initial members merged into the stored NIP-43 list at start-up.
    pub members: Vec<MemberCfg>,
}

impl Default for AuthCfg {
    fn default() -> Self {
        AuthCfg {
            reads: Access::Open,
            writes: Access::Members,
            admins: Vec::new(),
            membership_source: "nip43".into(),
            members: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct IngestCfg {
    pub max_pending_oks: usize,
    pub max_writer_connections: usize,
    pub queue_size: usize,
    pub max_event_bytes: usize,
}

impl Default for IngestCfg {
    fn default() -> Self {
        IngestCfg {
            max_pending_oks: 5_000,
            max_writer_connections: 8,
            queue_size: 20_000,
            max_event_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardrailsCfg {
    pub operation_deadline_ms: u64,
    pub batch_deadline_ms: u64,
    pub max_depth: u8,
    pub max_reached_nodes: usize,
    pub max_walk_records: usize,
    pub max_statement_limit: usize,
    pub max_path_nodes: usize,
    pub max_neighborhood_limit: usize,
    pub max_batch_items: usize,
    pub max_lookup_keys: usize,
    pub max_lookup_page: usize,
    pub max_lookup_batch: usize,
    pub max_lookup_records: usize,
    pub max_in_flight: usize,
    pub max_connections: usize,
    pub max_unsent_output: usize,
    pub max_message_length: usize,
}

impl Default for GuardrailsCfg {
    fn default() -> Self {
        let l = Limits::global_defaults();
        GuardrailsCfg {
            operation_deadline_ms: l.operation_deadline_ms,
            batch_deadline_ms: l.batch_deadline_ms,
            max_depth: l.max_depth,
            max_reached_nodes: l.max_reached_nodes,
            max_walk_records: l.max_walk_records,
            max_statement_limit: l.max_statement_limit,
            max_path_nodes: l.max_path_nodes,
            max_neighborhood_limit: l.max_neighborhood_limit,
            max_batch_items: l.max_batch_items,
            max_lookup_keys: l.max_lookup_keys,
            max_lookup_page: l.max_lookup_page,
            max_lookup_batch: l.max_lookup_batch,
            max_lookup_records: l.max_lookup_records,
            max_in_flight: l.max_in_flight,
            max_connections: 4,
            max_unsent_output: l.max_unsent_output,
            max_message_length: l.max_message_length,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageCfg {
    pub data_dir: String,
}

impl Default for StorageCfg {
    fn default() -> Self {
        StorageCfg {
            data_dir: "data".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminCfg {
    /// Defaults to `127.0.0.1:<protocol port + 1>`.
    pub listen: Option<String>,
    pub auth: String,
}

impl Default for AdminCfg {
    fn default() -> Self {
        AdminCfg {
            listen: None,
            auth: "local".into(),
        }
    }
}

impl Config {
    /// Effective limits.
    pub fn limits(&self, ingest: &IngestCfg) -> Limits {
        let g = &self.guardrails;
        Limits {
            operation_deadline_ms: g.operation_deadline_ms,
            batch_deadline_ms: g.batch_deadline_ms,
            max_depth: g.max_depth.clamp(1, 7),
            max_reached_nodes: g.max_reached_nodes,
            max_walk_records: g.max_walk_records,
            max_statement_limit: g.max_statement_limit,
            max_path_nodes: g.max_path_nodes,
            max_neighborhood_limit: g.max_neighborhood_limit,
            max_batch_items: g.max_batch_items,
            max_lookup_keys: g.max_lookup_keys,
            max_lookup_page: g.max_lookup_page,
            max_lookup_batch: g.max_lookup_batch,
            max_lookup_records: g.max_lookup_records,
            max_in_flight: g.max_in_flight,
            max_pending_oks: ingest.max_pending_oks,
            max_writer_connections: ingest.max_writer_connections,
            max_connections: g.max_connections,
            max_unsent_output: g.max_unsent_output,
            max_message_length: g.max_message_length,
        }
    }
}
