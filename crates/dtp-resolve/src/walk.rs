//! The exact walk (wot-model §6) with per-walk binding
//! (identity-binding.md §4) and guardrails (§6.2).

use std::collections::HashMap;
use std::time::Instant;

use dtp_graph::{Adj, BucketId, EdgeCols, EdgeId, Graph, NodeId, NodeType};
use dtp_model::KIND_TRUST;
use dtp_model::score::meets_threshold;

/// Binding mode (identity-binding.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum BindingMode {
    #[default]
    Lenient,
    Strict,
}

impl BindingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BindingMode::Lenient => "lenient",
            BindingMode::Strict => "strict",
        }
    }

    pub fn parse(value: &str) -> Option<BindingMode> {
        match value {
            "lenient" => Some(BindingMode::Lenient),
            "strict" => Some(BindingMode::Strict),
            _ => None,
        }
    }
}

/// Where the observer's own evidence came from (extension heap only; the
/// servers never have any).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnSource {
    Bio,
    Post,
}

/// Own evidence for one X account, already filtered to the query's root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnEvidence {
    pub x: NodeId,
    pub pubkey: NodeId,
    pub source: OwnSource,
}

/// Walk budgets (resolver-api § Guardrails).
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    pub max_nodes: usize,
    pub max_records: usize,
    pub deadline: Option<Instant>,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_nodes: 5_000_000,
            max_records: 50_000_000,
            deadline: None,
        }
    }
}

/// Why a walk stopped early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TruncReason {
    TimeBudget,
    NodeBudget,
    EdgeBudget,
}

impl TruncReason {
    pub fn as_str(self) -> &'static str {
        match self {
            TruncReason::TimeBudget => "timeBudget",
            TruncReason::NodeBudget => "nodeBudget",
            TruncReason::EdgeBudget => "edgeBudget",
        }
    }
}

/// Inputs of one walk.
#[derive(Clone, Debug)]
pub struct WalkParams {
    pub root: NodeId,
    /// The subject's node (`None`: no record ever named it).
    pub subject: Option<NodeId>,
    /// Score kind `K`.
    pub kind: u32,
    /// `Chain(32009, TC)`.
    pub hop_buckets: Vec<BucketId>,
    /// `Chain(K, SC)`.
    pub score_buckets: Vec<BucketId>,
    pub threshold: u64,
    pub max_depth: u8,
    pub now: u64,
    pub mode: BindingMode,
    pub own: Vec<OwnEvidence>,
    pub budgets: Budgets,
    /// Record counter contributions for the path format.
    pub track_contrib: bool,
}

/// Per reached node.
#[derive(Clone, Copy, Debug, Default)]
pub struct NodeState {
    pub level: u8,
    pub trust: u32,
    pub distrust: u32,
    pub neutral: u32,
    /// Level at which the node joined the frontier (reached by a `v=1` hop).
    pub frontier: Option<u8>,
}

/// Source of a bind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindSource {
    OwnBio,
    OwnPost,
    OwnStatement,
    Witness,
}

impl BindSource {
    pub fn as_str(self) -> &'static str {
        match self {
            BindSource::OwnBio => "own-bio",
            BindSource::OwnPost => "own-post",
            BindSource::OwnStatement => "own-statement",
            BindSource::Witness => "witness",
        }
    }
}

/// A bind decision for one X account at one level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub pubkey: NodeId,
    pub source: BindSource,
    pub witness: Option<EdgeId>,
    /// Level of the witness author (own statement = 0).
    pub witness_level: Option<u8>,
    pub claim: Option<[u8; 32]>,
}

/// Strict-mode cut explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cut {
    pub pubkey: NodeId,
    pub reason: &'static str,
}

/// `bind(R, X, ℓ)` outcome with provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindOutcome {
    pub bind: Option<Bind>,
    pub cut: Option<Cut>,
}

/// One evidence statement at the hitting degree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub author: NodeId,
    pub edge: EdgeId,
}

/// The outcome of a walk.
#[derive(Clone, Debug)]
pub struct WalkOutcome {
    pub connected: bool,
    pub degree: u8,
    pub hits: Vec<Hit>,
    /// Level of the last hit check (`degree − 1` when connected).
    pub last_level: u8,
    /// The subject's node at the hitting (or last checked) level.
    pub subject_node: Option<NodeId>,
    pub truncated: Option<TruncReason>,
    pub complete_depth: u8,
    pub states: HashMap<NodeId, NodeState>,
    /// Frontier per level: `levels[ℓ]` = nodes that joined at level ℓ.
    pub levels: Vec<Vec<NodeId>>,
    /// Counter contributions per node (path format only).
    pub contrib: HashMap<NodeId, Vec<EdgeId>>,
    pub scanned: usize,
    /// Bind of a `user:id` subject at `last_level`.
    pub subject_bind: Option<BindOutcome>,
}

/// A walk in progress. Also used for `graph.field` (no subject).
pub struct Walker<'g> {
    pub g: &'g Graph,
    pub p: WalkParams,
    pub states: HashMap<NodeId, NodeState>,
    pub levels: Vec<Vec<NodeId>>,
    pub contrib: HashMap<NodeId, Vec<EdgeId>>,
    bound: HashMap<NodeId, BindOutcome>,
    pub scanned: usize,
}

const DEADLINE_CHECK_EVERY: usize = 4096;

impl<'g> Walker<'g> {
    pub fn new(g: &'g Graph, p: WalkParams) -> Walker<'g> {
        let mut states = HashMap::new();
        states.insert(
            p.root,
            NodeState {
                level: 0,
                frontier: Some(0),
                ..Default::default()
            },
        );
        let levels = vec![vec![p.root]];
        Walker {
            g,
            p,
            states,
            levels,
            contrib: HashMap::new(),
            bound: HashMap::new(),
            scanned: 0,
        }
    }

    /// `qualifies(A, G)`.
    pub fn qualifies(&self, a: NodeId) -> bool {
        if a == self.p.root {
            return true;
        }
        self.states.get(&a).is_some_and(|s| {
            meets_threshold(u64::from(s.trust), u64::from(s.distrust), self.p.threshold)
        })
    }

    fn in_frontier_at_most(&self, a: NodeId, level: u8) -> Option<u8> {
        self.states
            .get(&a)
            .and_then(|s| s.frontier)
            .filter(|&f| f <= level)
    }

    fn active(&self, entry_window: bool, edge: &EdgeCols) -> bool {
        !entry_window || edge.is_active_at(self.p.now)
    }

    // ---------------------------------------------------------------- binds

    fn claim_of(&self, p: NodeId, twitter_id: &str) -> Option<[u8; 32]> {
        self.g.claim(p, twitter_id)
    }

    fn cut_reason(&self, p: NodeId) -> &'static str {
        match self.g.claim_slot(p).and_then(|s| s.winner.as_ref()) {
            Some(w) if !w.twitter_ids.is_empty() => "false-hint",
            _ => "no-claim",
        }
    }

    /// A single author's witness for X: newest active witness statement.
    fn witnesses_by_author(&self, x: NodeId) -> HashMap<NodeId, EdgeId> {
        let mut best: HashMap<NodeId, EdgeId> = HashMap::new();
        for &e in self.g.witness_edges(x) {
            let edge = self.g.edge(e);
            if !edge.is_active_at(self.p.now) {
                continue;
            }
            best.entry(edge.author)
                .and_modify(|cur| {
                    let c = self.g.edge(*cur);
                    if (edge.created_at, std::cmp::Reverse(edge.id))
                        > (c.created_at, std::cmp::Reverse(c.id))
                    {
                        *cur = e;
                    }
                })
                .or_insert(e);
        }
        best
    }

    /// `bind(R, X, ℓ)` for a bindable X node.
    pub fn bind(&mut self, x: NodeId, level: u8) -> BindOutcome {
        if let Some(done) = self.bound.get(&x) {
            return done.clone();
        }
        let outcome = self.compute_bind(x, level);
        // Bound answers never change at deeper levels; own evidence and own
        // witnesses are level-independent.
        let stable = outcome.bind.is_some()
            || self.p.own.iter().any(|o| o.x == x)
            || outcome.cut.is_some() && self.own_witness(x).is_some();
        if stable {
            self.bound.insert(x, outcome.clone());
        }
        outcome
    }

    /// Binds decided so far (sorted by X node key).
    pub fn bound_list(&self) -> Vec<(NodeId, Bind)> {
        let mut out: Vec<(NodeId, Bind)> = self
            .bound
            .iter()
            .filter_map(|(&x, o)| o.bind.clone().map(|b| (x, b)))
            .collect();
        out.sort_by_key(|(x, _)| self.g.node(*x).key.value());
        out
    }

    fn own_witness(&self, x: NodeId) -> Option<EdgeId> {
        self.witnesses_by_author(x).get(&self.p.root).copied()
    }

    fn decide_single(
        &self,
        twitter_id: &str,
        pubkey: NodeId,
        source: BindSource,
        witness: Option<EdgeId>,
        witness_level: Option<u8>,
    ) -> BindOutcome {
        let claim = self.claim_of(pubkey, twitter_id);
        if self.p.mode == BindingMode::Strict && claim.is_none() {
            return BindOutcome {
                bind: None,
                cut: Some(Cut {
                    pubkey,
                    reason: self.cut_reason(pubkey),
                }),
            };
        }
        BindOutcome {
            bind: Some(Bind {
                pubkey,
                source,
                witness,
                witness_level,
                claim,
            }),
            cut: None,
        }
    }

    fn compute_bind(&self, x: NodeId, level: u8) -> BindOutcome {
        let Some(twitter_id) = self.g.node(x).key.twitter_id() else {
            return BindOutcome {
                bind: None,
                cut: None,
            };
        };
        // Step 1: own evidence (Bio beats linking post).
        let own = self
            .p
            .own
            .iter()
            .filter(|o| o.x == x)
            .min_by_key(|o| match o.source {
                OwnSource::Bio => 0,
                OwnSource::Post => 1,
            });
        if let Some(own) = own {
            let source = match own.source {
                OwnSource::Bio => BindSource::OwnBio,
                OwnSource::Post => BindSource::OwnPost,
            };
            return self.decide_single(&twitter_id, own.pubkey, source, None, None);
        }
        let witnesses = self.witnesses_by_author(x);
        // Step 2: own witness.
        if let Some(&e) = witnesses.get(&self.p.root) {
            let hint = self.g.edge(e).hint.expect("witness has a hint");
            return self.decide_single(
                &twitter_id,
                hint,
                BindSource::OwnStatement,
                Some(e),
                Some(0),
            );
        }
        // Steps 3–5: WoT witnesses by qualifying frontier authors at ≤ level.
        struct Cand {
            level: u8,
            trust: u32,
            created_at: u64,
            author_key: String,
            edge: EdgeId,
            pubkey: NodeId,
        }
        let mut cands: Vec<Cand> = witnesses
            .iter()
            .filter_map(|(&author, &e)| {
                let lvl = self.in_frontier_at_most(author, level)?;
                if !self.qualifies(author) {
                    return None;
                }
                let edge = self.g.edge(e);
                Some(Cand {
                    level: lvl,
                    trust: self.states.get(&author).map_or(0, |s| s.trust),
                    created_at: edge.created_at,
                    author_key: self.g.node(author).key.value(),
                    edge: e,
                    pubkey: edge.hint.expect("witness has a hint"),
                })
            })
            .collect();
        cands.sort_by(|a, b| {
            a.level
                .cmp(&b.level)
                .then(b.trust.cmp(&a.trust))
                .then(b.created_at.cmp(&a.created_at))
                .then(a.author_key.cmp(&b.author_key))
        });
        let top_cut = cands.first().map(|c| c.pubkey);
        for c in &cands {
            let claim = self.claim_of(c.pubkey, &twitter_id);
            if self.p.mode == BindingMode::Strict && claim.is_none() {
                continue;
            }
            return BindOutcome {
                bind: Some(Bind {
                    pubkey: c.pubkey,
                    source: BindSource::Witness,
                    witness: Some(c.edge),
                    witness_level: Some(c.level),
                    claim,
                }),
                cut: None,
            };
        }
        BindOutcome {
            bind: None,
            cut: top_cut.map(|p| Cut {
                pubkey: p,
                reason: self.cut_reason(p),
            }),
        }
    }

    /// `resolve(node, ℓ)`: the bound pubkey for a bindable X, else the node.
    /// `None` for an unbound X (terminal).
    pub fn resolve_node(&mut self, node: NodeId, level: u8) -> Option<NodeId> {
        if self.g.node(node).is_bindable() {
            self.bind(node, level).bind.map(|b| b.pubkey)
        } else {
            Some(node)
        }
    }

    /// The subject's node as seen at level ℓ.
    pub fn subject_at(&mut self, level: u8) -> Option<NodeId> {
        let s = self.p.subject?;
        if self.g.node(s).is_bindable() {
            Some(self.bind(s, level).bind.map_or(s, |b| b.pubkey))
        } else {
            Some(s)
        }
    }

    // ------------------------------------------------------------ selection

    /// Selects one statement per author over `buckets` (in chain order) from
    /// the in-runs of `sources`, keeping authors accepted by `keep`.
    fn select_in(
        &self,
        adj: Adj,
        sources: &[NodeId],
        buckets: &[BucketId],
        mut keep: impl FnMut(NodeId) -> bool,
    ) -> HashMap<NodeId, (usize, EdgeId)> {
        let mut best: HashMap<NodeId, (usize, EdgeId)> = HashMap::new();
        for (pos, &bucket) in buckets.iter().enumerate() {
            for &source in sources {
                for (entry, e) in self.g.bucket(adj, source, bucket) {
                    let author = entry.node();
                    if !keep(author) {
                        continue;
                    }
                    let edge = self.g.edge(e);
                    if !self.active(entry.has_window(), edge) {
                        continue;
                    }
                    match best.get(&author) {
                        None => {
                            best.insert(author, (pos, e));
                        }
                        Some(&(p, cur)) if p == pos => {
                            if edge.tie_break(self.g.edge(cur)).is_lt() {
                                best.insert(author, (pos, e));
                            }
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        best
    }

    /// In-edge sources of subject node `ns` at level ℓ: the node itself plus
    /// every X account bound to it at ℓ.
    fn sources_for(&mut self, ns: NodeId, level: u8) -> Vec<NodeId> {
        let mut sources = vec![ns];
        if self.g.node(ns).ty == NodeType::P {
            let xs: Vec<NodeId> = self.g.hinted_as(ns).collect();
            for x in xs {
                if self.bind(x, level).bind.is_some_and(|b| b.pubkey == ns) {
                    sources.push(x);
                }
            }
            for own in self.p.own.clone() {
                if own.pubkey == ns
                    && !sources.contains(&own.x)
                    && self.bind(own.x, level).bind.is_some_and(|b| b.pubkey == ns)
                {
                    sources.push(own.x);
                }
            }
        }
        sources
    }

    /// Evidence at degree `level + 1`.
    fn hits_at(&mut self, level: u8) -> (Option<NodeId>, Vec<Hit>) {
        let Some(ns) = self.subject_at(level) else {
            return (None, Vec::new());
        };
        let sources = self.sources_for(ns, level);
        let frontier: std::collections::HashSet<NodeId> = self.levels[level as usize]
            .iter()
            .copied()
            .filter(|&a| a != ns && self.qualifies(a))
            .collect();
        let adj = Adj::incoming(self.p.kind);
        let buckets = self.p.score_buckets.clone();
        let best = self.select_in(adj, &sources, &buckets, |a| frontier.contains(&a));
        let mut hits: Vec<Hit> = best
            .into_iter()
            .map(|(author, (_, edge))| Hit { author, edge })
            .collect();
        hits.sort_by_key(|h| h.edge);
        (Some(ns), hits)
    }

    fn counted(&self, hits: &[Hit]) -> usize {
        if self.p.kind == KIND_TRUST {
            hits.iter()
                .filter(|h| self.g.edge(h.edge).trust_value().is_some_and(|v| v != 0))
                .count()
        } else {
            hits.len()
        }
    }

    /// Hop statements of author `a` at level ℓ: one per resolved peer.
    fn select_out(
        &mut self,
        a: NodeId,
        level: u8,
    ) -> Result<Vec<(NodeId, EdgeId, i8)>, TruncReason> {
        let mut best: HashMap<NodeId, (usize, EdgeId, i8)> = HashMap::new();
        let buckets = self.p.hop_buckets.clone();
        let g = self.g;
        for (pos, &bucket) in buckets.iter().enumerate() {
            for (entry, e) in g.bucket(Adj::TrustOut, a, bucket) {
                self.scanned += 1;
                if self.scanned.is_multiple_of(DEADLINE_CHECK_EVERY) && self.deadline_passed() {
                    return Err(TruncReason::TimeBudget);
                }
                let edge = g.edge(e);
                if !self.active(entry.has_window(), edge) {
                    continue;
                }
                let Some(peer) = self.resolve_node(entry.node(), level) else {
                    continue;
                };
                if self.g.node(peer).ty != NodeType::P {
                    continue;
                }
                let value = entry.trust_value();
                match best.get(&peer) {
                    None => {
                        best.insert(peer, (pos, e, value));
                    }
                    Some(&(p, cur, _)) if p == pos => {
                        if self.g.edge(e).tie_break(self.g.edge(cur)).is_lt() {
                            best.insert(peer, (pos, e, value));
                        }
                    }
                    Some(_) => {}
                }
            }
        }
        let mut out: Vec<(NodeId, EdgeId, i8)> = best
            .into_iter()
            .map(|(peer, (_, e, v))| (peer, e, v))
            .collect();
        out.sort_by_key(|(_, e, _)| *e);
        Ok(out)
    }

    fn deadline_passed(&self) -> bool {
        self.p.budgets.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Records the expansion needs at level ℓ (upper bound, deterministic).
    fn expansion_cost(&self, authors: &[NodeId]) -> usize {
        authors
            .iter()
            .map(|&a| {
                self.p
                    .hop_buckets
                    .iter()
                    .map(|&b| self.g.bucket_len(Adj::TrustOut, a, b))
                    .sum::<usize>()
            })
            .sum()
    }

    /// Builds level `level + 1` from the frontier at `level`, skipping
    /// `skip` (the subject for 32009). Returns `Ok(false)` when the new
    /// frontier is empty.
    pub fn expand(&mut self, level: u8, skip: Option<NodeId>) -> Result<bool, TruncReason> {
        if self.deadline_passed() {
            return Err(TruncReason::TimeBudget);
        }
        let d = level + 1;
        let authors: Vec<NodeId> = self.levels[level as usize]
            .iter()
            .copied()
            .filter(|&a| self.qualifies(a) && (Some(a) != skip || a == self.p.root))
            .collect();
        let cost = self.expansion_cost(&authors);
        if self.scanned + cost > self.p.budgets.max_records {
            return Err(TruncReason::EdgeBudget);
        }
        let mut picks: Vec<(NodeId, NodeId, EdgeId, i8)> = Vec::new();
        for &a in &authors {
            for (peer, e, v) in self.select_out(a, level)? {
                picks.push((a, peer, e, v));
            }
        }
        let mut new_nodes: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        for &(_, peer, _, _) in &picks {
            if !self.states.contains_key(&peer) {
                new_nodes.insert(peer);
            }
        }
        if self.states.len() + new_nodes.len() > self.p.budgets.max_nodes {
            return Err(TruncReason::NodeBudget);
        }
        let mut next = Vec::new();
        for (_, peer, e, v) in picks {
            let state = self.states.entry(peer).or_insert(NodeState {
                level: d,
                ..Default::default()
            });
            if state.level < d {
                continue;
            }
            match v {
                1 => state.trust += 1,
                -1 => state.distrust += 1,
                _ => state.neutral += 1,
            }
            if v == 1 && state.frontier.is_none() {
                state.frontier = Some(d);
                next.push(peer);
            }
            if self.p.track_contrib {
                self.contrib.entry(peer).or_default().push(e);
            }
        }
        next.sort_unstable();
        let nonempty = !next.is_empty();
        self.levels.push(next);
        Ok(nonempty)
    }

    /// Whether any record can address the subject (early return).
    fn subject_has_evidence_sources(&self) -> bool {
        let Some(s) = self.p.subject else {
            return false;
        };
        let adj = Adj::incoming(self.p.kind);
        let has_in = |n: NodeId| {
            self.p
                .score_buckets
                .iter()
                .any(|&b| self.g.bucket_len(adj, n, b) > 0)
        };
        if has_in(s) {
            return true;
        }
        if self.g.node(s).is_bindable() {
            let own = self.p.own.iter().filter(|o| o.x == s).map(|o| o.pubkey);
            let hinted = self
                .g
                .witness_edges(s)
                .iter()
                .filter_map(|&e| self.g.edge(e).hint);
            return own.chain(hinted).any(has_in);
        }
        if self.g.node(s).ty == NodeType::P {
            return self.g.hinted_as(s).any(has_in)
                || self.p.own.iter().any(|o| o.pubkey == s && has_in(o.x));
        }
        false
    }

    fn finish(
        mut self,
        degree: u8,
        hits: Vec<Hit>,
        last_level: u8,
        subject_node: Option<NodeId>,
        truncated: Option<TruncReason>,
        complete_depth: u8,
    ) -> WalkOutcome {
        let subject_bind = match self.p.subject {
            Some(s) if self.g.node(s).is_bindable() => Some(self.bind(s, last_level)),
            _ => None,
        };
        WalkOutcome {
            subject_bind,
            connected: degree > 0,
            degree,
            hits,
            last_level,
            subject_node,
            truncated,
            complete_depth,
            states: self.states,
            levels: self.levels,
            contrib: self.contrib,
            scanned: self.scanned,
        }
    }

    /// Runs the full walk for the subject.
    pub fn run(mut self) -> WalkOutcome {
        if !self.subject_has_evidence_sources() {
            let ns = self.p.subject;
            return self.finish(0, Vec::new(), 0, ns, None, 0);
        }
        let mut last_ns = self.p.subject;
        for d in 1..=self.p.max_depth {
            let level = d - 1;
            let (ns, hits) = self.hits_at(level);
            last_ns = ns;
            if self.counted(&hits) > 0 {
                return self.finish(d, hits, level, ns, None, level);
            }
            if d == self.p.max_depth {
                break;
            }
            let skip = if self.p.kind == KIND_TRUST { ns } else { None };
            match self.expand(level, skip) {
                Ok(true) => {}
                Ok(false) => return self.finish(0, Vec::new(), level, ns, None, d),
                Err(reason) => {
                    // The partial level was never applied.
                    self.levels.truncate(level as usize + 1);
                    return self.finish(0, Vec::new(), level, ns, Some(reason), level);
                }
            }
        }
        let last = self.p.max_depth - 1;
        self.finish(0, Vec::new(), last, last_ns, None, last)
    }
}
