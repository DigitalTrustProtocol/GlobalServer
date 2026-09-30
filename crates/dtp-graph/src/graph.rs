//! The graph snapshot and its single-writer mutations.
//!
//! `Graph` is a persistent value: cloning it is O(1) (every table is an `im`
//! map or an `Arc`), so the writer mutates its own copy and publishes clones
//! as immutable epoch snapshots. Reads never lock.

use std::sync::Arc;

use dtp_model::{ClaimRecord, EdgeRecord, KIND_IDENTITY, KIND_RATING, KIND_TRUST, RecordValue};

use crate::contexts::ContextTable;
use crate::csr::{Csr, Run, RunSlice};
use crate::entry::{Entry, trust_code};
use crate::nodes::{NodeInfo, NodeKey, NodeTable, NodeType};
use crate::{BucketId, EdgeId, NodeId};

/// The `d` part of a slot address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DKey {
    Hex([u8; 32]),
    Str(Arc<str>),
}

impl DKey {
    pub fn parse(d: &str) -> DKey {
        match dtp_model::hex32(d) {
            Some(bytes) => DKey::Hex(bytes),
            None => DKey::Str(Arc::from(d)),
        }
    }

    pub fn value(&self) -> String {
        match self {
            DKey::Hex(b) => hex::encode(b),
            DKey::Str(s) => s.to_string(),
        }
    }
}

/// Slot identity `(kind, author, d)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SlotKey {
    pub kind: u32,
    pub author: NodeId,
    pub d: DKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Winner {
    pub id: [u8; 32],
    pub created_at: u64,
    /// Graph edge of the winner; `None` for a Delete winner.
    pub edge: Option<EdgeId>,
}

/// Slot state: the current winner and the NIP-09 floor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlotState {
    pub winner: Option<Winner>,
    pub floor: Option<u64>,
}

/// Display fields; never change results except the rating label filter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Display {
    pub content: String,
    pub labels: Vec<String>,
    pub label_hints: Vec<(String, String)>,
}

/// Cold columns of one live (non-Delete) winner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeCols {
    pub id: [u8; 32],
    pub author: NodeId,
    pub subject: NodeId,
    pub kind: u32,
    pub bucket: BucketId,
    pub created_at: u64,
    pub d: DKey,
    pub value: RecordValue,
    pub activate: Option<u64>,
    pub expire: Option<u64>,
    pub scope_rank: u8,
    pub hint: Option<NodeId>,
    /// Person statement (32009 about `p` or `user:id`): has a `trust_out` entry.
    pub person: bool,
    pub display: Option<Arc<Display>>,
}

impl EdgeCols {
    pub fn is_active_at(&self, t: u64) -> bool {
        self.activate.is_none_or(|x| t >= x) && self.expire.is_none_or(|y| t <= y)
    }

    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    pub fn trust_value(&self) -> Option<i8> {
        match self.value {
            RecordValue::Trust(v) => Some(v),
            RecordValue::Score(_) => None,
        }
    }

    /// Model §4.3 tie-break: higher `scopeRank`, newer, lower id.
    /// `Less` means `self` wins.
    pub fn tie_break(&self, other: &EdgeCols) -> std::cmp::Ordering {
        other
            .scope_rank
            .cmp(&self.scope_rank)
            .then(other.created_at.cmp(&self.created_at))
            .then(self.id.cmp(&other.id))
    }

    pub fn content(&self) -> &str {
        self.display.as_ref().map_or("", |d| d.content.as_str())
    }

    pub fn labels(&self) -> &[String] {
        self.display.as_ref().map_or(&[], |d| d.labels.as_slice())
    }

    pub fn label_hints(&self) -> &[(String, String)] {
        self.display
            .as_ref()
            .map_or(&[], |d| d.label_hints.as_slice())
    }
}

/// Which CSR to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adj {
    /// Authors of 32009 statements, keyed by subject.
    TrustIn,
    /// Subjects of person 32009 statements (`p`, `user:id`), keyed by author.
    TrustOut,
    /// Authors of 32014 ratings, keyed by subject.
    RatingIn,
}

impl Adj {
    pub fn incoming(kind: u32) -> Adj {
        if kind == KIND_RATING {
            Adj::RatingIn
        } else {
            Adj::TrustIn
        }
    }
}

/// Outcome of applying one record or claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// New slot winner (`replaced`: an older winner was removed).
    Accepted { replaced: bool },
    /// Same event already stored.
    Duplicate,
    /// Older than (or losing the tie-break to) the stored winner.
    Older,
    /// At or below the slot's NIP-09 floor, or deleted by id.
    Deleted,
}

/// Outcome of a NIP-09 deletion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeletionOutcome {
    pub removed: usize,
    pub floors: usize,
    pub tombstones: usize,
}

/// Replaceable kind 10011 state of one author.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClaimSlot {
    pub winner: Option<ClaimWinner>,
    pub floor: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimWinner {
    pub id: [u8; 32],
    pub created_at: u64,
    /// X accounts claimed by the winner (empty: no claim).
    pub twitter_ids: Vec<Arc<str>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum IdRef {
    Slot(SlotKey),
    Claim(NodeId),
}

/// Dead-edge bits over base edge ids (persistent, word-level copy-on-write).
#[derive(Clone, Debug, Default)]
pub struct DeadBits {
    words: im::Vector<u64>,
    count: usize,
}

impl DeadBits {
    pub fn get(&self, id: EdgeId) -> bool {
        let w = (id / 64) as usize;
        w < self.words.len() && self.words[w] & (1 << (id % 64)) != 0
    }

    pub fn set(&mut self, id: EdgeId) {
        let w = (id / 64) as usize;
        while self.words.len() <= w {
            self.words.push_back(0);
        }
        let bit = 1u64 << (id % 64);
        if self.words[w] & bit == 0 {
            self.words[w] |= bit;
            self.count += 1;
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

/// Immutable base segment (one CSR per adjacency).
#[derive(Clone, Debug, Default)]
pub struct Base {
    pub trust_in: Csr,
    pub trust_out: Csr,
    pub rating_in: Csr,
    /// Edges with ids below this limit live in the base.
    pub edge_limit: EdgeId,
}

impl Base {
    fn csr(&self, adj: Adj) -> &Csr {
        match adj {
            Adj::TrustIn => &self.trust_in,
            Adj::TrustOut => &self.trust_out,
            Adj::RatingIn => &self.rating_in,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Delta {
    trust_in: im::HashMap<NodeId, Arc<Run>>,
    trust_out: im::HashMap<NodeId, Arc<Run>>,
    rating_in: im::HashMap<NodeId, Arc<Run>>,
}

impl Delta {
    fn map(&self, adj: Adj) -> &im::HashMap<NodeId, Arc<Run>> {
        match adj {
            Adj::TrustIn => &self.trust_in,
            Adj::TrustOut => &self.trust_out,
            Adj::RatingIn => &self.rating_in,
        }
    }

    fn map_mut(&mut self, adj: Adj) -> &mut im::HashMap<NodeId, Arc<Run>> {
        match adj {
            Adj::TrustIn => &mut self.trust_in,
            Adj::TrustOut => &mut self.trust_out,
            Adj::RatingIn => &mut self.rating_in,
        }
    }
}

/// Size and memory counters for telemetry and the bytes-per-edge estimate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphStats {
    pub nodes: usize,
    pub trust_edges: usize,
    pub rating_edges: usize,
    pub claims: usize,
    pub hinted_statements: usize,
    pub delete_floors: usize,
    pub dead_edges: usize,
    /// Packed hot format (entries + edge ids + directories), base + delta.
    pub hot_bytes: usize,
    /// Cold columns estimate.
    pub cold_bytes: usize,
    /// Node keys and tables.
    pub core_bytes: usize,
}

/// A graph snapshot.
#[derive(Clone, Debug, Default)]
pub struct Graph {
    epoch: u64,
    nodes: NodeTable,
    contexts: ContextTable,
    edges: im::Vector<Option<Arc<EdgeCols>>>,
    base: Arc<Base>,
    dead: DeadBits,
    delta: Delta,
    other_out: im::HashMap<NodeId, Arc<Vec<EdgeId>>>,
    slots: im::HashMap<SlotKey, SlotState>,
    ids: im::HashMap<[u8; 32], IdRef>,
    tombstones: im::HashMap<[u8; 32], NodeId>,
    claim_slots: im::HashMap<NodeId, ClaimSlot>,
    claims_by_x: im::HashMap<Arc<str>, Arc<Vec<(NodeId, [u8; 32])>>>,
    witness_in: im::HashMap<NodeId, Arc<Vec<EdgeId>>>,
    hinted_as: im::HashMap<NodeId, Arc<Vec<(NodeId, u32)>>>,
    live_trust: usize,
    live_rating: usize,
    hinted: usize,
    floors: usize,
}

fn cow_run(map: &mut im::HashMap<NodeId, Arc<Run>>, node: NodeId) -> &mut Run {
    Arc::make_mut(map.entry(node).or_default())
}

impl Graph {
    pub fn new() -> Graph {
        Graph::default()
    }

    /// Epoch number (`graphVersion`).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    // ---------------------------------------------------------------- reads

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Node for a subject value (lowercased).
    pub fn node_id(&self, value: &str) -> Option<NodeId> {
        self.nodes.get(&NodeKey::parse(value))
    }

    pub fn node(&self, id: NodeId) -> &NodeInfo {
        self.nodes.info(id)
    }

    pub fn contexts(&self) -> &ContextTable {
        &self.contexts
    }

    pub fn edge(&self, id: EdgeId) -> &EdgeCols {
        self.edges[id as usize]
            .as_deref()
            .expect("edge referenced by a run is live")
    }

    pub fn try_edge(&self, id: EdgeId) -> Option<&EdgeCols> {
        self.edges.get(id as usize).and_then(|e| e.as_deref())
    }

    /// `(Entry, EdgeId)` pairs of one bucket of one node, base (minus dead)
    /// then delta.
    pub fn bucket(
        &self,
        adj: Adj,
        node: NodeId,
        bucket: BucketId,
    ) -> impl Iterator<Item = (Entry, EdgeId)> + '_ {
        let base = self.base.csr(adj).bucket(node, bucket);
        let delta = self
            .delta
            .map(adj)
            .get(&node)
            .map_or(RunSlice::EMPTY, |r| r.bucket(bucket));
        base.iter()
            .filter(move |(_, id)| !self.dead.get(*id))
            .chain(delta.iter())
    }

    /// Upper bound of entries in one bucket (includes dead base entries).
    pub fn bucket_len(&self, adj: Adj, node: NodeId, bucket: BucketId) -> usize {
        let base = self.base.csr(adj).bucket(node, bucket).len();
        let delta = self
            .delta
            .map(adj)
            .get(&node)
            .map_or(0, |r| r.bucket(bucket).len());
        base + delta
    }

    /// Buckets a node has entries in (sorted, deduplicated).
    pub fn buckets(&self, adj: Adj, node: NodeId) -> Vec<BucketId> {
        let mut out: Vec<BucketId> = self.base.csr(adj).buckets(node).collect();
        if let Some(run) = self.delta.map(adj).get(&node) {
            out.extend(run.buckets());
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Non-person outgoing winners of an author (post / event / other `i`
    /// trust, and ratings): the in-memory stand-in for the store's
    /// `by_author` scan.
    pub fn other_out(&self, author: NodeId) -> &[EdgeId] {
        self.other_out.get(&author).map_or(&[], |v| v.as_slice())
    }

    /// Hinted `v=1`, `x.com` statements about X by authors other than the
    /// hinted pubkey (witness candidates; activity is checked by readers).
    pub fn witness_edges(&self, x: NodeId) -> &[EdgeId] {
        self.witness_in.get(&x).map_or(&[], |v| v.as_slice())
    }

    /// X accounts some witness statement hints to `p`.
    pub fn hinted_as(&self, p: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.hinted_as
            .get(&p)
            .into_iter()
            .flat_map(|v| v.iter().map(|(x, _)| *x))
    }

    /// Kind 10011 state of an author.
    pub fn claim_slot(&self, p: NodeId) -> Option<&ClaimSlot> {
        self.claim_slots.get(&p)
    }

    /// Whether `p`'s winning 10011 names `twitter_id`, with the claim id.
    pub fn claim(&self, p: NodeId, twitter_id: &str) -> Option<[u8; 32]> {
        let winner = self.claim_slots.get(&p)?.winner.as_ref()?;
        winner
            .twitter_ids
            .iter()
            .any(|x| &**x == twitter_id)
            .then_some(winner.id)
    }

    /// Every pubkey whose valid winner claims `twitter_id`, sorted by pubkey.
    pub fn claims_for(&self, twitter_id: &str) -> Vec<(NodeId, [u8; 32])> {
        let mut out: Vec<(NodeId, [u8; 32])> = self
            .claims_by_x
            .get(twitter_id)
            .map(|v| v.as_ref().clone())
            .unwrap_or_default();
        out.sort_by_key(|(p, _)| self.node(*p).key.value());
        out
    }

    pub fn slot(&self, key: &SlotKey) -> Option<&SlotState> {
        self.slots.get(key)
    }

    /// Slot of a stored event id.
    pub fn slot_of_id(&self, id: &[u8; 32]) -> Option<SlotKey> {
        match self.ids.get(id)? {
            IdRef::Slot(key) => Some(key.clone()),
            IdRef::Claim(_) => None,
        }
    }

    /// Whether an event id is currently stored (winner of a slot or claim).
    pub fn has_id(&self, id: &[u8; 32]) -> bool {
        self.ids.contains_key(id)
    }

    /// Author of the kind 10011 winner with this id.
    pub fn claim_of_id(&self, id: &[u8; 32]) -> Option<NodeId> {
        match self.ids.get(id)? {
            IdRef::Claim(p) => Some(*p),
            IdRef::Slot(_) => None,
        }
    }

    /// Whether a deletion tombstone is pending for this id.
    pub fn is_tombstoned(&self, id: &[u8; 32]) -> bool {
        self.tombstones.contains_key(id)
    }

    /// Slot key for `(kind, pubkey, d)` if the author is known.
    pub fn slot_key(&self, kind: u32, pubkey: &str, d: &str) -> Option<SlotKey> {
        Some(SlotKey {
            kind,
            author: self.node_id(pubkey)?,
            d: DKey::parse(d),
        })
    }

    /// `(winner present, floor)` of a slot; kind 10011 reads the claim slot.
    pub fn slot_status(&self, kind: u32, pubkey: &str, d: &str) -> (bool, Option<u64>) {
        if kind == KIND_IDENTITY {
            let slot = self.node_id(pubkey).and_then(|p| self.claim_slots.get(&p));
            return slot.map_or((false, None), |s| (s.winner.is_some(), s.floor));
        }
        let state = self
            .slot_key(kind, pubkey, d)
            .and_then(|k| self.slots.get(&k));
        state.map_or((false, None), |s| (s.winner.is_some(), s.floor))
    }

    /// Restores a NIP-09 floor at start-up.
    pub fn restore_floor(&mut self, kind: u32, pubkey: &str, d: &str, floor: u64) {
        let author = self.intern_pubkey(pubkey);
        if kind == KIND_IDENTITY {
            let slot = self.claim_slots.entry(author).or_default();
            slot.floor = Some(slot.floor.map_or(floor, |f| f.max(floor)));
            return;
        }
        let key = SlotKey {
            kind,
            author,
            d: DKey::parse(d),
        };
        let mut state = self.slots.get(&key).cloned().unwrap_or_default();
        self.set_floor(&mut state, floor);
        self.slots.insert(key, state);
    }

    /// Restores a pending tombstone at start-up.
    pub fn restore_tombstone(&mut self, id: &str, deleter: &str) {
        if let Some(id) = dtp_model::hex32(id) {
            let deleter = self.intern_pubkey(deleter);
            self.tombstones.insert(id, deleter);
        }
    }

    pub fn stats(&self) -> GraphStats {
        let base = &self.base;
        let delta_bytes: usize = [Adj::TrustIn, Adj::TrustOut, Adj::RatingIn]
            .iter()
            .map(|&adj| {
                self.delta
                    .map(adj)
                    .values()
                    .map(|r| r.len() * 8 + r.dir.len() * 12)
                    .sum::<usize>()
            })
            .sum();
        let hot =
            base.trust_in.bytes() + base.trust_out.bytes() + base.rating_in.bytes() + delta_bytes;
        let cold = self.edges.iter().flatten().map(|e| {
            96 + e.display.as_ref().map_or(0, |d| {
                d.content.len()
                    + d.labels.iter().map(String::len).sum::<usize>()
                    + d.label_hints
                        .iter()
                        .map(|(a, b)| a.len() + b.len())
                        .sum::<usize>()
            })
        });
        GraphStats {
            nodes: self.nodes.len(),
            trust_edges: self.live_trust,
            rating_edges: self.live_rating,
            claims: self.claims_by_x.values().map(|v| v.len()).sum(),
            hinted_statements: self.hinted,
            delete_floors: self.floors,
            dead_edges: self.dead.count(),
            hot_bytes: hot,
            cold_bytes: cold.sum(),
            core_bytes: self.nodes.key_bytes() + self.nodes.len() * 12,
        }
    }

    // --------------------------------------------------------------- writes

    /// Interns a pubkey node.
    pub fn intern_pubkey(&mut self, pubkey: &str) -> NodeId {
        self.nodes.intern(NodeKey::parse(pubkey), NodeType::P)
    }

    fn alloc_edge(&mut self, cols: EdgeCols) -> EdgeId {
        let id = self.edges.len() as EdgeId;
        self.edges.push_back(Some(Arc::new(cols)));
        id
    }

    fn is_person(&self, cols: &EdgeCols) -> bool {
        cols.person
    }

    fn link(&mut self, id: EdgeId) {
        let cols = Arc::clone(self.edges[id as usize].as_ref().expect("live edge"));
        let window = cols.activate.is_some() || cols.expire.is_some();
        match cols.kind {
            KIND_TRUST => {
                let code = trust_code(cols.trust_value().unwrap_or(0));
                cow_run(&mut self.delta.trust_in, cols.subject).insert(
                    cols.bucket,
                    Entry::pack(cols.author, code, window, false),
                    id,
                );
                if self.is_person(&cols) {
                    cow_run(&mut self.delta.trust_out, cols.author).insert(
                        cols.bucket,
                        Entry::pack(cols.subject, code, window, false),
                        id,
                    );
                } else {
                    Arc::make_mut(self.other_out.entry(cols.author).or_default()).push(id);
                }
                if let Some(hint) = cols.hint {
                    self.hinted += 1;
                    if cols.trust_value() == Some(1) && hint != cols.author {
                        Arc::make_mut(self.witness_in.entry(cols.subject).or_default()).push(id);
                        let list = Arc::make_mut(self.hinted_as.entry(hint).or_default());
                        match list.iter_mut().find(|(x, _)| *x == cols.subject) {
                            Some((_, n)) => *n += 1,
                            None => list.push((cols.subject, 1)),
                        }
                    }
                }
                self.live_trust += 1;
            }
            KIND_RATING => {
                cow_run(&mut self.delta.rating_in, cols.subject).insert(
                    cols.bucket,
                    Entry::pack(cols.author, 0, window, false),
                    id,
                );
                Arc::make_mut(self.other_out.entry(cols.author).or_default()).push(id);
                self.live_rating += 1;
            }
            _ => unreachable!("only 32009 / 32014 edges"),
        }
    }

    fn unlink(&mut self, id: EdgeId) {
        let Some(cols) = self.edges[id as usize].clone() else {
            return;
        };
        let in_base = id < self.base.edge_limit;
        let remove = |g: &mut Graph, adj: Adj, node: NodeId| {
            if let Some(run) = g.delta.map_mut(adj).get_mut(&node) {
                Arc::make_mut(run).remove(cols.bucket, id);
                if run.is_empty() {
                    g.delta.map_mut(adj).remove(&node);
                }
            }
        };
        match cols.kind {
            KIND_TRUST => {
                if in_base {
                    self.dead.set(id);
                } else {
                    remove(self, Adj::TrustIn, cols.subject);
                    if self.is_person(&cols) {
                        remove(self, Adj::TrustOut, cols.author);
                    }
                }
                if !self.is_person(&cols) {
                    self.remove_other_out(cols.author, id);
                }
                if let Some(hint) = cols.hint {
                    self.hinted -= 1;
                    if cols.trust_value() == Some(1) && hint != cols.author {
                        if let Some(list) = self.witness_in.get_mut(&cols.subject) {
                            Arc::make_mut(list).retain(|&e| e != id);
                        }
                        if let Some(list) = self.hinted_as.get_mut(&hint) {
                            let list = Arc::make_mut(list);
                            if let Some(pos) = list.iter().position(|(x, _)| *x == cols.subject) {
                                list[pos].1 -= 1;
                                if list[pos].1 == 0 {
                                    list.remove(pos);
                                }
                            }
                        }
                    }
                }
                self.live_trust -= 1;
            }
            KIND_RATING => {
                if in_base {
                    self.dead.set(id);
                } else {
                    remove(self, Adj::RatingIn, cols.subject);
                }
                self.remove_other_out(cols.author, id);
                self.live_rating -= 1;
            }
            _ => {}
        }
        self.edges[id as usize] = None;
    }

    fn remove_other_out(&mut self, author: NodeId, id: EdgeId) {
        if let Some(list) = self.other_out.get_mut(&author) {
            Arc::make_mut(list).retain(|&e| e != id);
            if list.is_empty() {
                self.other_out.remove(&author);
            }
        }
    }

    fn set_floor(&mut self, state: &mut SlotState, floor: u64) {
        if state.floor.is_none() {
            self.floors += 1;
        }
        state.floor = Some(state.floor.map_or(floor, |f| f.max(floor)));
    }

    /// Applies a normalized record under the slot-winner rule (model §2.4).
    pub fn apply_record(&mut self, record: &EdgeRecord) -> ApplyOutcome {
        let id = dtp_model::hex32(&record.id).unwrap_or_else(|| {
            use sha2::{Digest, Sha256};
            Sha256::digest(record.id.as_bytes()).into()
        });
        let author = self.intern_pubkey(&record.pubkey);
        let key = SlotKey {
            kind: record.kind,
            author,
            d: DKey::parse(&record.d),
        };
        let mut state = self.slots.get(&key).cloned().unwrap_or_default();

        if let Some(&deleter) = self.tombstones.get(&id)
            && deleter == author
        {
            self.tombstones.remove(&id);
            self.set_floor(&mut state, record.created_at);
            self.slots.insert(key, state);
            return ApplyOutcome::Deleted;
        }
        if state.floor.is_some_and(|f| record.created_at <= f) {
            return ApplyOutcome::Deleted;
        }
        let mut replaced = false;
        if let Some(w) = &state.winner {
            if w.id == id {
                return ApplyOutcome::Duplicate;
            }
            let newer = record.created_at > w.created_at
                || (record.created_at == w.created_at && id < w.id);
            if !newer {
                return ApplyOutcome::Older;
            }
            if let Some(edge) = w.edge {
                self.unlink(edge);
            }
            self.ids.remove(&w.id);
            replaced = true;
        }

        let edge = record.value.map(|value| {
            let subject_ty = NodeType::from_subject(record.subject_type);
            let subject = self
                .nodes
                .intern(NodeKey::parse(&record.subject), subject_ty);
            let bucket = self.contexts.intern(record.kind, &record.context);
            let hint = record.hint_pubkey.as_deref().map(|h| self.intern_pubkey(h));
            let display = (!record.content.is_empty()
                || !record.labels.is_empty()
                || !record.label_hints.is_empty())
            .then(|| {
                Arc::new(Display {
                    content: record.content.clone(),
                    labels: record.labels.clone(),
                    label_hints: record.label_hints.clone(),
                })
            });
            let cols = EdgeCols {
                id,
                author,
                subject,
                kind: record.kind,
                bucket,
                created_at: record.created_at,
                d: key.d.clone(),
                value,
                activate: record.activate,
                expire: record.expire,
                scope_rank: record.scope_rank,
                hint,
                person: record.kind == KIND_TRUST
                    && (subject_ty == NodeType::P || self.nodes.info(subject).is_bindable()),
                display,
            };
            let edge = self.alloc_edge(cols);
            self.link(edge);
            edge
        });
        state.winner = Some(Winner {
            id,
            created_at: record.created_at,
            edge,
        });
        self.ids.insert(id, IdRef::Slot(key.clone()));
        self.slots.insert(key, state);
        ApplyOutcome::Accepted { replaced }
    }

    /// Removes a slot's winner outright (conformance `remove` op; also used
    /// by retention). Leaves no floor.
    pub fn remove_slot(&mut self, kind: u32, pubkey: &str, d: &str) -> bool {
        let Some(author) = self.node_id(pubkey) else {
            return false;
        };
        let key = SlotKey {
            kind,
            author,
            d: DKey::parse(d),
        };
        let Some(state) = self.slots.get(&key).cloned() else {
            return false;
        };
        let Some(w) = state.winner else {
            return false;
        };
        if let Some(edge) = w.edge {
            self.unlink(edge);
        }
        self.ids.remove(&w.id);
        if state.floor.is_some() {
            self.slots.insert(
                key,
                SlotState {
                    winner: None,
                    floor: state.floor,
                },
            );
        } else {
            self.slots.remove(&key);
        }
        true
    }

    fn set_claim_index(&mut self, p: NodeId, id: [u8; 32], ids: &[Arc<str>], add: bool) {
        for x in ids {
            let entry = self.claims_by_x.entry(x.clone()).or_default();
            let list = Arc::make_mut(entry);
            list.retain(|(q, _)| *q != p);
            if add {
                list.push((p, id));
            }
            if list.is_empty() {
                self.claims_by_x.remove(x);
            }
        }
    }

    /// Applies a kind 10011 as the author's replaceable winner.
    pub fn apply_claim(&mut self, claim: &ClaimRecord) -> ApplyOutcome {
        let ids: Vec<Arc<str>> = claim
            .twitter_id
            .iter()
            .map(|x| Arc::from(x.as_str()))
            .collect();
        self.apply_claim_ids(&claim.pubkey, &claim.id, claim.created_at, ids)
    }

    /// Applies a claim with an explicit X account list.
    pub fn apply_claim_ids(
        &mut self,
        pubkey: &str,
        event_id: &str,
        created_at: u64,
        twitter_ids: Vec<Arc<str>>,
    ) -> ApplyOutcome {
        let id = dtp_model::hex32(event_id).unwrap_or_else(|| {
            use sha2::{Digest, Sha256};
            Sha256::digest(event_id.as_bytes()).into()
        });
        let p = self.intern_pubkey(pubkey);
        let mut slot = self.claim_slots.get(&p).cloned().unwrap_or_default();
        if let Some(&deleter) = self.tombstones.get(&id)
            && deleter == p
        {
            self.tombstones.remove(&id);
            slot.floor = Some(slot.floor.map_or(created_at, |f| f.max(created_at)));
            self.claim_slots.insert(p, slot);
            return ApplyOutcome::Deleted;
        }
        if slot.floor.is_some_and(|f| created_at <= f) {
            return ApplyOutcome::Deleted;
        }
        let mut replaced = false;
        if let Some(w) = &slot.winner {
            if w.id == id {
                return ApplyOutcome::Duplicate;
            }
            let newer = created_at > w.created_at || (created_at == w.created_at && id < w.id);
            if !newer {
                return ApplyOutcome::Older;
            }
            let old = w.clone();
            self.set_claim_index(p, old.id, &old.twitter_ids, false);
            self.ids.remove(&old.id);
            replaced = true;
        }
        self.set_claim_index(p, id, &twitter_ids, true);
        slot.winner = Some(ClaimWinner {
            id,
            created_at,
            twitter_ids,
        });
        self.ids.insert(id, IdRef::Claim(p));
        self.claim_slots.insert(p, slot);
        ApplyOutcome::Accepted { replaced }
    }

    /// Drops an author's claim winner (conformance `unclaim`).
    pub fn remove_claim(&mut self, pubkey: &str) -> bool {
        let Some(p) = self.node_id(pubkey) else {
            return false;
        };
        let Some(slot) = self.claim_slots.get(&p).cloned() else {
            return false;
        };
        let Some(w) = slot.winner else {
            return false;
        };
        self.set_claim_index(p, w.id, &w.twitter_ids, false);
        self.ids.remove(&w.id);
        self.claim_slots.insert(
            p,
            ClaimSlot {
                winner: None,
                floor: slot.floor,
            },
        );
        true
    }

    /// Applies a NIP-09 deletion by `deleter`.
    pub fn apply_deletion(&mut self, deletion: &dtp_model::Deletion) -> DeletionOutcome {
        let mut out = DeletionOutcome::default();
        let deleter = self.intern_pubkey(&deletion.pubkey);
        for target in &deletion.targets {
            match target {
                dtp_model::DeletionTarget::Event(hex_id) => {
                    let Some(id) = dtp_model::hex32(hex_id) else {
                        continue;
                    };
                    match self.ids.get(&id).cloned() {
                        Some(IdRef::Slot(key)) if key.author == deleter => {
                            let mut state = self.slots.get(&key).cloned().unwrap_or_default();
                            if let Some(w) = state.winner.clone()
                                && w.id == id
                            {
                                if let Some(edge) = w.edge {
                                    self.unlink(edge);
                                }
                                self.ids.remove(&id);
                                state.winner = None;
                                self.set_floor(&mut state, w.created_at);
                                self.slots.insert(key, state);
                                out.removed += 1;
                                out.floors += 1;
                            }
                        }
                        Some(IdRef::Claim(p)) if p == deleter => {
                            let mut slot = self.claim_slots.get(&p).cloned().unwrap_or_default();
                            if let Some(w) = slot.winner.clone()
                                && w.id == id
                            {
                                self.set_claim_index(p, w.id, &w.twitter_ids, false);
                                self.ids.remove(&id);
                                slot.winner = None;
                                slot.floor =
                                    Some(slot.floor.map_or(w.created_at, |f| f.max(w.created_at)));
                                self.claim_slots.insert(p, slot);
                                out.removed += 1;
                                out.floors += 1;
                            }
                        }
                        Some(_) => {}
                        None => {
                            self.tombstones.insert(id, deleter);
                            out.tombstones += 1;
                        }
                    }
                }
                dtp_model::DeletionTarget::Address { kind, pubkey, d } => {
                    if pubkey != &deletion.pubkey {
                        continue;
                    }
                    if *kind == KIND_IDENTITY {
                        let mut slot = self.claim_slots.get(&deleter).cloned().unwrap_or_default();
                        slot.floor = Some(
                            slot.floor
                                .map_or(deletion.created_at, |f| f.max(deletion.created_at)),
                        );
                        if let Some(w) = slot.winner.clone()
                            && w.created_at <= deletion.created_at
                        {
                            self.set_claim_index(deleter, w.id, &w.twitter_ids, false);
                            self.ids.remove(&w.id);
                            slot.winner = None;
                            out.removed += 1;
                        }
                        self.claim_slots.insert(deleter, slot);
                        out.floors += 1;
                        continue;
                    }
                    if *kind != KIND_TRUST && *kind != KIND_RATING {
                        continue;
                    }
                    let key = SlotKey {
                        kind: *kind,
                        author: deleter,
                        d: DKey::parse(d),
                    };
                    let mut state = self.slots.get(&key).cloned().unwrap_or_default();
                    self.set_floor(&mut state, deletion.created_at);
                    if let Some(w) = state.winner.clone()
                        && w.created_at <= deletion.created_at
                    {
                        if let Some(edge) = w.edge {
                            self.unlink(edge);
                        }
                        self.ids.remove(&w.id);
                        state.winner = None;
                        out.removed += 1;
                    }
                    self.slots.insert(key, state);
                    out.floors += 1;
                }
            }
        }
        out
    }

    /// Folds the delta into a new base segment (a base rebuild): all live
    /// entries are rewritten as dense CSRs, dead bits are cleared.
    pub fn compact(&mut self) {
        let n = self.nodes.len();
        let build = |g: &Graph, adj: Adj| {
            let mut per_node = vec![Vec::new(); n];
            for (node, items) in per_node.iter_mut().enumerate() {
                let node = node as NodeId;
                for bucket in g.buckets(adj, node) {
                    items.extend(g.bucket(adj, node, bucket).map(|(e, id)| (bucket, e, id)));
                }
            }
            Csr::build(n, per_node)
        };
        let base = Base {
            trust_in: build(self, Adj::TrustIn),
            trust_out: build(self, Adj::TrustOut),
            rating_in: build(self, Adj::RatingIn),
            edge_limit: self.edges.len() as EdgeId,
        };
        self.base = Arc::new(base);
        self.delta = Delta::default();
        self.dead = DeadBits::default();
    }

    /// Number of entries in the delta tier (for flush decisions and metrics).
    pub fn delta_entries(&self) -> usize {
        [Adj::TrustIn, Adj::TrustOut, Adj::RatingIn]
            .iter()
            .map(|&adj| self.delta.map(adj).values().map(|r| r.len()).sum::<usize>())
            .sum()
    }
}
