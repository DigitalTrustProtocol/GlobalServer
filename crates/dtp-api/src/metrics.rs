//! Counters behind `/metrics` and `/admin/api/telemetry` (TrustGraph
//! telemetry.md). Aggregates only: no subjects, roots, or IPs.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::{Value, json};

pub const INGEST_KINDS: [u32; 4] = [32009, 32014, 10011, 5];
pub const INGEST_RESULTS: [&str; 6] = [
    "accepted",
    "duplicate",
    "invalid",
    "blocked",
    "rate_limited",
    "deleted",
];
pub const OP_RESULTS: [&str; 5] = ["ok", "busy", "rate_limited", "invalid", "error"];
const LATENCY_BUCKETS: [f64; 10] = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

#[derive(Clone, Debug)]
pub struct WriterStat {
    pub pubkey: Option<String>,
    pub connected_since: f64,
    pub events: u64,
    pub rejects: u64,
}

#[derive(Default)]
struct Latency {
    recent: VecDeque<f64>,
    buckets: [u64; 10],
    count: u64,
    sum: f64,
}

#[derive(Default)]
pub struct Metrics {
    ingest: Mutex<HashMap<(u32, &'static str), u64>>,
    rejects_by_prefix: Mutex<BTreeMap<String, u64>>,
    pub deletions: AtomicU64,
    ops: Mutex<BTreeMap<(String, &'static str), u64>>,
    latency: Mutex<BTreeMap<String, Latency>>,
    guardrails: Mutex<BTreeMap<String, u64>>,
    connections: Mutex<HashMap<(&'static str, &'static str), i64>>,
    pub authentications: AtomicU64,
    pub slow_disconnects: AtomicU64,
    pub in_flight: AtomicUsize,
    pub pending_oks: AtomicUsize,
    pub queue_depth: AtomicUsize,
    writers: Mutex<BTreeMap<u64, WriterStat>>,
    logs: Mutex<VecDeque<(f64, &'static str, String)>>,
    rates: Mutex<Rates>,
}

/// Last sample time, counters at that time, and the derived per-second rates.
#[derive(Default)]
struct Rates {
    at: f64,
    ingest: HashMap<u32, u64>,
    ops: HashMap<String, u64>,
    ingest_rate: BTreeMap<u32, f64>,
    ops_rate: BTreeMap<String, f64>,
}

pub fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl Metrics {
    pub fn ingest(&self, kind: u32, result: &'static str, prefix: Option<&str>) {
        let kind = if INGEST_KINDS.contains(&kind) {
            kind
        } else {
            0
        };
        *self
            .ingest
            .lock()
            .unwrap()
            .entry((kind, result))
            .or_default() += 1;
        if let Some(p) = prefix {
            *self
                .rejects_by_prefix
                .lock()
                .unwrap()
                .entry(p.to_string())
                .or_default() += 1;
        }
    }

    pub fn op(&self, op: &str, result: &'static str, seconds: Option<f64>) {
        *self
            .ops
            .lock()
            .unwrap()
            .entry((op.to_string(), result))
            .or_default() += 1;
        if let Some(s) = seconds {
            let mut lat = self.latency.lock().unwrap();
            let l = lat.entry(op.to_string()).or_default();
            if l.recent.len() >= 2048 {
                l.recent.pop_front();
            }
            l.recent.push_back(s);
            l.count += 1;
            l.sum += s;
            for (i, b) in LATENCY_BUCKETS.iter().enumerate() {
                if s <= *b {
                    l.buckets[i] += 1;
                }
            }
        }
    }

    pub fn guardrail(&self, reason: &str) {
        *self
            .guardrails
            .lock()
            .unwrap()
            .entry(reason.to_string())
            .or_default() += 1;
    }

    pub fn connection(&self, role: &'static str, origin: &'static str, delta: i64) {
        *self
            .connections
            .lock()
            .unwrap()
            .entry((role, origin))
            .or_default() += delta;
    }

    pub fn writer_update(&self, conn: u64, stat: Option<WriterStat>) {
        let mut w = self.writers.lock().unwrap();
        match stat {
            Some(s) => {
                w.insert(conn, s);
            }
            None => {
                w.remove(&conn);
            }
        }
    }

    pub fn writer_event(&self, conn: u64, rejected: bool) {
        if let Some(s) = self.writers.lock().unwrap().get_mut(&conn) {
            s.events += 1;
            if rejected {
                s.rejects += 1;
            }
        }
    }

    pub fn log(&self, level: &'static str, message: String) {
        match level {
            "error" => tracing::error!("{message}"),
            _ => tracing::warn!("{message}"),
        }
        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= 1000 {
            logs.pop_front();
        }
        logs.push_back((now_f64(), level, message));
    }

    /// Recomputes per-second rates (called every few seconds).
    pub fn sample_rates(&self) {
        let now = now_f64();
        let ingest: HashMap<u32, u64> = {
            let i = self.ingest.lock().unwrap();
            INGEST_KINDS
                .iter()
                .map(|k| (*k, i.get(&(*k, "accepted")).copied().unwrap_or(0)))
                .collect()
        };
        let ops: HashMap<String, u64> = {
            let mut m: HashMap<String, u64> = HashMap::new();
            for ((op, _), n) in self.ops.lock().unwrap().iter() {
                *m.entry(op.clone()).or_default() += n;
            }
            m
        };
        let mut r = self.rates.lock().unwrap();
        let dt = now - r.at;
        if r.at > 0.0 && dt > 0.0 {
            let mut ev = BTreeMap::new();
            for k in INGEST_KINDS {
                let prev = r.ingest.get(&k).copied().unwrap_or(0);
                ev.insert(k, (ingest.get(&k).copied().unwrap_or(0) - prev) as f64 / dt);
            }
            let mut ops_rate = BTreeMap::new();
            for (op, n) in &ops {
                let prev = r.ops.get(op).copied().unwrap_or(0);
                ops_rate.insert(op.clone(), (n - prev) as f64 / dt);
            }
            r.ingest_rate = ev;
            r.ops_rate = ops_rate;
        }
        r.at = now;
        r.ingest = ingest;
        r.ops = ops;
    }

    fn percentile(sorted: &[f64], p: f64) -> Value {
        if sorted.is_empty() {
            return Value::Null;
        }
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        json!(sorted[idx.min(sorted.len() - 1)])
    }

    pub fn ingest_json(&self) -> (Value, Value, Value) {
        let i = self.ingest.lock().unwrap();
        let mut by_kind = serde_json::Map::new();
        for k in INGEST_KINDS {
            let mut counts = serde_json::Map::new();
            for r in INGEST_RESULTS {
                counts.insert(r.into(), json!(i.get(&(k, r)).copied().unwrap_or(0)));
            }
            by_kind.insert(k.to_string(), Value::Object(counts));
        }
        let rates = self.rates.lock().unwrap();
        let mut eps = serde_json::Map::new();
        for k in INGEST_KINDS {
            eps.insert(
                k.to_string(),
                json!(rates.ingest_rate.get(&k).copied().unwrap_or(0.0)),
            );
        }
        let prefixes: serde_json::Map<String, Value> = self
            .rejects_by_prefix
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        (
            Value::Object(eps),
            Value::Object(by_kind),
            Value::Object(prefixes),
        )
    }

    pub fn writers_json(&self) -> Value {
        Value::Array(
            self.writers
                .lock()
                .unwrap()
                .values()
                .map(|w| json!({ "pubkey": w.pubkey, "connectedSince": w.connected_since, "events": w.events, "rejects": w.rejects }))
                .collect(),
        )
    }

    pub fn queries_json(&self) -> Value {
        let ops = self.ops.lock().unwrap();
        let mut totals: BTreeMap<String, serde_json::Map<String, Value>> = BTreeMap::new();
        for ((op, result), n) in ops.iter() {
            let entry = totals.entry(op.clone()).or_insert_with(|| {
                OP_RESULTS
                    .iter()
                    .map(|r| (r.to_string(), json!(0)))
                    .collect()
            });
            entry.insert(result.to_string(), json!(n));
        }
        let mut latency = serde_json::Map::new();
        for (op, l) in self.latency.lock().unwrap().iter() {
            let mut sorted: Vec<f64> = l.recent.iter().copied().collect();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let ms: Vec<f64> = sorted.iter().map(|s| s * 1000.0).collect();
            let warm = json!({ "p50": Self::percentile(&ms, 0.5), "p95": Self::percentile(&ms, 0.95), "p99": Self::percentile(&ms, 0.99), "count": l.count });
            let cold = json!({ "p50": null, "p95": null, "p99": null, "count": 0 });
            latency.insert(op.clone(), json!({ "warm": warm, "cold": cold }));
        }
        let rates = self.rates.lock().unwrap();
        let guard: serde_json::Map<String, Value> = self
            .guardrails
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        json!({
            "opsPerSecond": rates.ops_rate,
            "totals": totals,
            "latency": latency,
            "inFlight": self.in_flight.load(Ordering::Relaxed),
            "guardrailHits": guard,
            "backgroundCompletions": 0,
            "fieldCache": null,
        })
    }

    pub fn connections_json(&self) -> Value {
        let c = self.connections.lock().unwrap();
        let mut by_role: BTreeMap<&str, i64> =
            ["anonymous_reader", "member_reader", "writer", "admin"]
                .iter()
                .map(|r| (*r, 0))
                .collect();
        let mut by_origin: BTreeMap<&str, i64> = ["extension", "native", "other"]
            .iter()
            .map(|r| (*r, 0))
            .collect();
        let mut open = 0;
        for ((role, origin), n) in c.iter() {
            *by_role.entry(role).or_default() += n;
            *by_origin.entry(origin).or_default() += n;
            open += n;
        }
        json!({
            "open": open.max(0),
            "byRole": by_role,
            "byOrigin": by_origin,
            "authentications": self.authentications.load(Ordering::Relaxed),
            "slowClientDisconnects": self.slow_disconnects.load(Ordering::Relaxed),
        })
    }

    pub fn logs_json(&self) -> Value {
        Value::Array(
            self.logs
                .lock()
                .unwrap()
                .iter()
                .map(|(ts, level, message)| json!({ "ts": ts, "level": level, "message": message }))
                .collect(),
        )
    }

    /// Prometheus text for the counters this struct owns.
    pub fn prometheus(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = writeln!(out, "# TYPE dtp_ingest_events_total counter");
        for ((kind, result), n) in self.ingest.lock().unwrap().iter() {
            let _ = writeln!(
                out,
                "dtp_ingest_events_total{{kind=\"{kind}\",result=\"{result}\"}} {n}"
            );
        }
        let _ = writeln!(out, "# TYPE dtp_operations_total counter");
        for ((op, result), n) in self.ops.lock().unwrap().iter() {
            let _ = writeln!(
                out,
                "dtp_operations_total{{op=\"{op}\",result=\"{result}\"}} {n}"
            );
        }
        let _ = writeln!(out, "# TYPE dtp_operation_duration_seconds histogram");
        for (op, l) in self.latency.lock().unwrap().iter() {
            for (i, b) in LATENCY_BUCKETS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "dtp_operation_duration_seconds_bucket{{op=\"{op}\",temperature=\"warm\",le=\"{b}\"}} {}",
                    l.buckets[i]
                );
            }
            let _ = writeln!(
                out,
                "dtp_operation_duration_seconds_bucket{{op=\"{op}\",temperature=\"warm\",le=\"+Inf\"}} {}",
                l.count
            );
            let _ = writeln!(
                out,
                "dtp_operation_duration_seconds_sum{{op=\"{op}\",temperature=\"warm\"}} {}",
                l.sum
            );
            let _ = writeln!(
                out,
                "dtp_operation_duration_seconds_count{{op=\"{op}\",temperature=\"warm\"}} {}",
                l.count
            );
        }
        let _ = writeln!(out, "# TYPE dtp_operations_inflight gauge");
        let _ = writeln!(
            out,
            "dtp_operations_inflight {}",
            self.in_flight.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE dtp_guardrail_hits_total counter");
        for (reason, n) in self.guardrails.lock().unwrap().iter() {
            let _ = writeln!(out, "dtp_guardrail_hits_total{{reason=\"{reason}\"}} {n}");
        }
        let _ = writeln!(out, "# TYPE dtp_connections gauge");
        for ((role, origin), n) in self.connections.lock().unwrap().iter() {
            let _ = writeln!(
                out,
                "dtp_connections{{role=\"{role}\",origin=\"{origin}\"}} {n}"
            );
        }
        let _ = writeln!(out, "# TYPE dtp_ingest_queue_depth gauge");
        let _ = writeln!(
            out,
            "dtp_ingest_queue_depth {}",
            self.queue_depth.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE dtp_ingest_pending_oks gauge");
        let _ = writeln!(
            out,
            "dtp_ingest_pending_oks {}",
            self.pending_oks.load(Ordering::Relaxed)
        );
        let _ = writeln!(out, "# TYPE dtp_source_state gauge");
        for w in self.writers.lock().unwrap().values() {
            if let Some(pk) = &w.pubkey {
                let _ = writeln!(out, "dtp_source_state{{source=\"{pk}\",type=\"writer\"}} 1");
            }
        }
    }
}
