//! Root field (resolver-engine.md § Root field): the walk's level structure
//! built once per `(root, TC, G, D, bindingMode, now)` and reused to answer
//! every subject by a hit test over the stored levels.
//!
//! Valid (equal to the exact walk) when `K = 32014`, or `K = 32009` with
//! `SC = TC`; [`Field::serves`] checks that. The property "field = walk" is
//! asserted over every conformance case.

use std::collections::HashMap;

use dtp_graph::{BucketId, Graph, NodeId};
use dtp_model::{KIND_RATING, KIND_TRUST};

use crate::walk::{TruncReason, WalkOutcome, WalkParams, Walker};

/// A built root field.
pub struct Field<'g> {
    walker: Walker<'g>,
    hop_context: String,
    complete_depth: u8,
    truncated: Option<TruncReason>,
}

impl<'g> Field<'g> {
    /// Expands levels `1 ..= D − 1` from the root (no subject, nothing
    /// skipped), stopping early at an empty frontier or a budget.
    pub fn build(g: &'g Graph, mut params: WalkParams, hop_context: &str) -> Field<'g> {
        params.subject = None;
        params.track_contrib = false;
        let max_depth = params.max_depth;
        let mut walker = Walker::new(g, params);
        let mut complete_depth = max_depth.saturating_sub(1);
        let mut truncated = None;
        for level in 0..max_depth.saturating_sub(1) {
            match walker.expand(level, None) {
                Ok(true) => {}
                Ok(false) => break,
                Err(reason) => {
                    walker.levels.truncate(level as usize + 1);
                    complete_depth = level;
                    truncated = Some(reason);
                    break;
                }
            }
        }
        Field {
            walker,
            hop_context: hop_context.to_string(),
            complete_depth,
            truncated,
        }
    }

    /// Whether this field answers a query of kind `kind` with score context
    /// `context` exactly like the walk.
    pub fn serves(&self, kind: u32, context: &str) -> bool {
        kind == KIND_RATING || (kind == KIND_TRUST && context == self.hop_context)
    }

    /// Hit test for one subject (resolver-engine.md § Hit test).
    pub fn resolve(
        &mut self,
        subject: Option<NodeId>,
        kind: u32,
        score_buckets: &[BucketId],
    ) -> WalkOutcome {
        let max_depth = self.walker.p.max_depth;
        let mut last_level = 0;
        let mut last_ns = subject;
        let mut result = (0u8, Vec::new(), None);
        let searchable = self
            .walker
            .has_evidence_sources(subject, kind, score_buckets);
        for level in 0..max_depth {
            if !searchable {
                break;
            }
            if level as usize >= self.walker.levels.len() {
                break;
            }
            last_level = level;
            let (ns, hits) = self.walker.hits_for(subject, kind, score_buckets, level);
            last_ns = ns;
            if Walker::counted_for(self.walker.g, kind, &hits) > 0 {
                result = (level + 1, hits, None);
                break;
            }
            if level >= self.complete_depth && self.truncated.is_some() {
                result = (0, Vec::new(), self.truncated);
                break;
            }
        }
        let (degree, hits, truncated) = result;
        let subject_bind = match subject {
            Some(s) if self.walker.g.node(s).is_bindable() => Some(self.walker.bind(s, last_level)),
            _ => None,
        };
        WalkOutcome {
            connected: degree > 0,
            degree,
            hits,
            last_level,
            subject_node: last_ns,
            truncated,
            complete_depth: self.complete_depth,
            states: HashMap::new(),
            levels: Vec::new(),
            contrib: HashMap::new(),
            scanned: self.walker.scanned,
            subject_bind,
        }
    }

    pub fn complete_depth(&self) -> u8 {
        self.complete_depth
    }

    pub fn truncated(&self) -> Option<TruncReason> {
        self.truncated
    }
}
