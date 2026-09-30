//! Interned context buckets (graph-engine.md § Contexts).

use std::sync::Arc;

use dtp_model::grammar::context_chain;
use dtp_model::{KIND_RATING, KIND_TRUST};

use crate::BucketId;

/// A context bucket `B(kind, context)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketInfo {
    pub kind: u32,
    pub context: Arc<str>,
}

impl BucketInfo {
    /// `"<kind>"` or `"<kind>:<context>"`.
    pub fn name(&self) -> String {
        if self.context.is_empty() {
            self.kind.to_string()
        } else {
            format!("{}:{}", self.kind, self.context)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContextTable {
    index: im::HashMap<(u32, Arc<str>), BucketId>,
    info: im::Vector<BucketInfo>,
}

impl ContextTable {
    pub fn get(&self, kind: u32, context: &str) -> Option<BucketId> {
        self.index.get(&(kind, Arc::from(context))).copied()
    }

    pub fn info(&self, bucket: BucketId) -> &BucketInfo {
        &self.info[bucket as usize]
    }

    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.info.is_empty()
    }

    pub fn intern(&mut self, kind: u32, context: &str) -> BucketId {
        if let Some(id) = self.get(kind, context) {
            return id;
        }
        let id = self.info.len() as BucketId;
        let context: Arc<str> = Arc::from(context);
        self.info.push_back(BucketInfo {
            kind,
            context: context.clone(),
        });
        self.index.insert((kind, context), id);
        id
    }

    /// `Chain(kind, C)` (model §4.2) restricted to buckets that exist:
    /// exact, parents, global for 32009; exact only for 32014 (G1 fixed).
    pub fn chain(&self, kind: u32, context: &str) -> Vec<BucketId> {
        match kind {
            KIND_TRUST => context_chain(context)
                .iter()
                .filter_map(|c| self.get(kind, c))
                .collect(),
            KIND_RATING => self.get(kind, context).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    /// The textual chain (bucket contexts) for a kind and context.
    pub fn chain_contexts(kind: u32, context: &str) -> Vec<String> {
        match kind {
            KIND_TRUST => context_chain(context),
            _ => vec![context.to_string()],
        }
    }

    /// Every bucket of a kind, ordered by context string.
    pub fn all_of_kind(&self, kind: u32) -> Vec<BucketId> {
        let mut buckets: Vec<(Arc<str>, BucketId)> = self
            .info
            .iter()
            .enumerate()
            .filter(|(_, b)| b.kind == kind)
            .map(|(i, b)| (b.context.clone(), i as BucketId))
            .collect();
        buckets.sort();
        buckets.into_iter().map(|(_, id)| id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chains() {
        let mut t = ContextTable::default();
        let g = t.intern(KIND_TRUST, "");
        let s = t.intern(KIND_TRUST, "security");
        let f = t.intern(KIND_TRUST, "security:access:frontdoor");
        let r = t.intern(KIND_RATING, "security");
        assert_eq!(
            t.chain(KIND_TRUST, "security:access:frontdoor"),
            vec![f, s, g]
        );
        assert_eq!(t.chain(KIND_TRUST, "security:access"), vec![s, g]);
        assert_eq!(t.chain(KIND_RATING, "security:access"), Vec::<u32>::new());
        assert_eq!(t.chain(KIND_RATING, "security"), vec![r]);
        assert_eq!(t.info(f).name(), "32009:security:access:frontdoor");
        assert_eq!(t.info(g).name(), "32009");
    }
}
