//! Ingest: pre-validation (connection side, CPU on the blocking pool) and
//! the single graph writer thread (ingest-storage.md § Validation pipeline).

use std::collections::BTreeSet;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use dtp_graph::{ApplyOutcome, Graph};
use dtp_model::statement::parse_statement;
use dtp_model::{
    ClaimRecord, Deletion, DeletionTarget, EdgeRecord, Event, KIND_DELETION, KIND_IDENTITY,
    KIND_RATING, KIND_TRUST, ScopeProfile,
};
use dtp_store::{SlotAddr, WriteOp};

use crate::state::{AppState, GraphChange};

/// A validated event ready for the writer.
#[derive(Clone, Debug)]
pub enum IngestPayload {
    Record(Box<EdgeRecord>),
    Claim(Box<ClaimRecord>),
    Deletion(Box<Deletion>),
}

pub struct IngestJob {
    pub event: Event,
    pub payload: IngestPayload,
    pub reply: oneshot::Sender<(bool, String)>,
}

/// Messages to the graph writer thread.
pub enum WriterMsg {
    Job(IngestJob),
    Stop,
}

/// A refusal: `(accepted, message, metrics result)`.
pub type Refusal = (bool, String, &'static str);

/// Stages 1 and 3–6: shape, kind, id, signature, NIP rules, scope profile.
pub fn prepare(event: &Event, profile: ScopeProfile) -> Result<IngestPayload, Refusal> {
    if event.check_shape().is_err() {
        return Err((
            false,
            "invalid: event does not have a valid shape".into(),
            "invalid",
        ));
    }
    if let Err(e) = event.verify() {
        return Err((false, format!("invalid: {e}"), "invalid"));
    }
    let first = |errors: Vec<dtp_model::ValidationError>| {
        let msg = errors
            .first()
            .map(|e| e.message.clone())
            .unwrap_or_default();
        (false, format!("invalid: {msg}"), "invalid")
    };
    match event.kind {
        KIND_TRUST | KIND_RATING => {
            let parsed = parse_statement(event, false).map_err(first)?;
            let record = parsed
                .normalize(profile)
                .map_err(|reason| (false, format!("blocked: {reason}"), "blocked"))?;
            Ok(IngestPayload::Record(Box::new(record)))
        }
        KIND_IDENTITY => Ok(IngestPayload::Claim(Box::new(
            dtp_model::parse_claim(event, false).map_err(first)?,
        ))),
        KIND_DELETION => {
            let deletion = dtp_model::parse_deletion(event, false).map_err(first)?;
            if !deletion.may_target_held_kinds() {
                return Err((
                    false,
                    "blocked: deletion does not target kinds 32009, 32014, 10011".into(),
                    "blocked",
                ));
            }
            Ok(IngestPayload::Deletion(Box::new(deletion)))
        }
        _ => Err((false, "blocked: kind not accepted".into(), "blocked")),
    }
}

fn subject_wire(record: &EdgeRecord) -> String {
    format!("{}:{}", record.subject_type.as_str(), record.subject)
}

struct Applied {
    ops: Vec<WriteOp>,
    reply: (bool, String),
    result: &'static str,
    changed: Option<String>,
}

fn apply_one(graph: &mut Graph, job: &IngestJob) -> Applied {
    let event = &job.event;
    let tombstoned = dtp_model::hex32(&event.id).is_some_and(|id| graph.is_tombstoned(&id));
    let (outcome, addr, changed) = match &job.payload {
        IngestPayload::Record(r) => {
            let addr = SlotAddr {
                kind: r.kind,
                pubkey: r.pubkey.clone(),
                d: r.d.clone(),
            };
            (graph.apply_record(r), addr, subject_wire(r))
        }
        IngestPayload::Claim(c) => {
            let addr = SlotAddr {
                kind: KIND_IDENTITY,
                pubkey: c.pubkey.clone(),
                d: String::new(),
            };
            (graph.apply_claim(c), addr, format!("p:{}", c.pubkey))
        }
        IngestPayload::Deletion(d) => return apply_deletion(graph, d),
    };
    match outcome {
        ApplyOutcome::Accepted { .. } => {
            let (_, floor) = graph.slot_status(addr.kind, &addr.pubkey, &addr.d);
            Applied {
                ops: vec![WriteOp::PutSlot {
                    addr,
                    event: Some(event.clone()),
                    floor,
                }],
                reply: (true, String::new()),
                result: "accepted",
                changed: Some(changed),
            }
        }
        ApplyOutcome::Duplicate => Applied {
            ops: vec![],
            reply: (true, "duplicate: already have this event".into()),
            result: "duplicate",
            changed: None,
        },
        ApplyOutcome::Older => Applied {
            ops: vec![],
            reply: (true, "duplicate: older than the stored winner".into()),
            result: "duplicate",
            changed: None,
        },
        ApplyOutcome::Deleted => {
            let mut ops = Vec::new();
            let (_, floor) = graph.slot_status(addr.kind, &addr.pubkey, &addr.d);
            if tombstoned && let Some(floor) = floor {
                ops.push(WriteOp::ClearTombstone {
                    id: event.id.clone(),
                });
                ops.push(WriteOp::SetFloor { addr, floor });
            }
            Applied {
                ops,
                reply: (false, "blocked: deleted".into()),
                result: "deleted",
                changed: None,
            }
        }
    }
}

fn apply_deletion(graph: &mut Graph, d: &Deletion) -> Applied {
    let mut affected: Vec<SlotAddr> = Vec::new();
    let mut tombstones: Vec<String> = Vec::new();
    for target in &d.targets {
        match target {
            DeletionTarget::Event(id) => {
                let Some(raw) = dtp_model::hex32(id) else {
                    continue;
                };
                if let Some(key) = graph.slot_of_id(&raw) {
                    affected.push(SlotAddr {
                        kind: key.kind,
                        pubkey: graph.node(key.author).key.value(),
                        d: key.d.value(),
                    });
                } else if let Some(p) = graph.claim_of_id(&raw) {
                    affected.push(SlotAddr {
                        kind: KIND_IDENTITY,
                        pubkey: graph.node(p).key.value(),
                        d: String::new(),
                    });
                } else if !graph.has_id(&raw) {
                    tombstones.push(id.clone());
                }
            }
            DeletionTarget::Address {
                kind,
                pubkey,
                d: dtag,
            } => {
                if matches!(*kind, KIND_TRUST | KIND_RATING | KIND_IDENTITY) && *pubkey == d.pubkey
                {
                    affected.push(SlotAddr {
                        kind: *kind,
                        pubkey: pubkey.clone(),
                        d: if *kind == KIND_IDENTITY {
                            String::new()
                        } else {
                            dtag.clone()
                        },
                    });
                }
            }
        }
    }
    graph.apply_deletion(d);
    let mut ops = Vec::new();
    for addr in affected {
        if addr.pubkey != d.pubkey {
            continue;
        }
        let (winner, floor) = graph.slot_status(addr.kind, &addr.pubkey, &addr.d);
        match (winner, floor) {
            (false, floor) => ops.push(WriteOp::PutSlot {
                addr,
                event: None,
                floor,
            }),
            (true, Some(floor)) => ops.push(WriteOp::SetFloor { addr, floor }),
            (true, None) => {}
        }
    }
    for id in tombstones {
        ops.push(WriteOp::Tombstone {
            id,
            deleter: d.pubkey.clone(),
        });
    }
    Applied {
        ops,
        reply: (true, String::new()),
        result: "accepted",
        changed: Some(format!("p:{}", d.pubkey)),
    }
}

/// Rebuilds the graph from the event store (winners were validated on write).
pub fn replay(
    store: &dyn dtp_store::EventStore,
    profile: ScopeProfile,
) -> anyhow::Result<(Graph, usize)> {
    let snap = store.snapshot()?;
    let mut graph = Graph::new();
    for (addr, floor) in &snap.floors {
        graph.restore_floor(addr.kind, &addr.pubkey, &addr.d, *floor);
    }
    for (id, deleter) in &snap.tombstones {
        graph.restore_tombstone(id, deleter);
    }
    let mut count = 0;
    for event in &snap.winners {
        match event.kind {
            KIND_TRUST | KIND_RATING => {
                if let Ok(parsed) = parse_statement(event, false)
                    && let Ok(record) = parsed.normalize(profile)
                {
                    graph.apply_record(&record);
                    count += 1;
                }
            }
            KIND_IDENTITY => {
                if let Ok(claim) = dtp_model::parse_claim(event, false) {
                    graph.apply_claim(&claim);
                    count += 1;
                }
            }
            _ => {}
        }
    }
    graph.compact();
    graph.set_epoch(1);
    Ok((graph, count))
}

/// The single graph writer: batches jobs, applies them to a copy of the
/// graph, commits the store, publishes the new epoch, then answers.
pub fn run_writer(state: Arc<AppState>, mut rx: mpsc::Receiver<WriterMsg>) {
    let mut graph: Graph = state.graph.load().as_ref().clone();
    let mut epoch = graph.epoch();
    let mut stopping = false;
    while !stopping {
        let Some(WriterMsg::Job(first)) = rx.blocking_recv() else {
            break;
        };
        let mut jobs = vec![first];
        while jobs.len() < 5_000 {
            match rx.try_recv() {
                Ok(WriterMsg::Job(job)) => jobs.push(job),
                Ok(WriterMsg::Stop) => {
                    stopping = true;
                    break;
                }
                Err(_) => break,
            }
        }
        state
            .metrics
            .queue_depth
            .store(rx.len(), std::sync::atomic::Ordering::Relaxed);
        let mut next = graph.clone();
        let mut ops = Vec::new();
        let mut outcomes = Vec::with_capacity(jobs.len());
        let mut changed: BTreeSet<String> = BTreeSet::new();
        for job in &jobs {
            let applied = apply_one(&mut next, job);
            ops.extend(applied.ops);
            if let Some(c) = applied.changed {
                changed.insert(c);
            }
            outcomes.push((applied.reply, applied.result));
        }
        let committed = ops.is_empty() || state.store.write(&ops).is_ok();
        if !committed {
            state
                .metrics
                .log("error", "event store write failed; batch rejected".into());
        }
        if committed && !changed.is_empty() {
            epoch += 1;
            next.set_epoch(epoch);
            if next.delta_entries() > 1_000_000 {
                next.compact();
            }
            graph = next;
            state.graph.store(Arc::new(graph.clone()));
            let subjects = if changed.len() <= 500 {
                changed.into_iter().collect()
            } else {
                Vec::new()
            };
            let _ = state.pushes.send(Arc::new(GraphChange {
                version: epoch,
                subjects,
            }));
        } else if committed {
            graph = next;
        }
        for (job, ((ok, msg), result)) in jobs.into_iter().zip(outcomes) {
            let kind = job.event.kind;
            let (ok, msg, result) = if committed {
                (ok, msg, result)
            } else {
                (false, "error: storage failure".to_string(), "invalid")
            };
            if kind == KIND_DELETION && result == "accepted" {
                state
                    .metrics
                    .deletions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let prefix = if ok && msg.is_empty() {
                None
            } else {
                msg.split(':').next()
            };
            state.metrics.ingest(
                kind,
                result,
                prefix.filter(|_| !ok || result == "duplicate"),
            );
            let _ = job.reply.send((ok, msg));
        }
    }
}
