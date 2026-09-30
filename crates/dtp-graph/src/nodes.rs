//! Node keys and the node table (graph-engine.md § Nodes).

use std::sync::Arc;

use crate::NodeId;

/// Node type. A hex key becomes `P` once it is seen as an author or a `p`
/// subject; `e` subjects and unbound `i` subjects are terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeType {
    P,
    E,
    I,
}

impl NodeType {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeType::P => "p",
            NodeType::E => "e",
            NodeType::I => "i",
        }
    }

    pub fn from_subject(ty: dtp_model::SubjectType) -> NodeType {
        match ty {
            dtp_model::SubjectType::P => NodeType::P,
            dtp_model::SubjectType::E => NodeType::E,
            dtp_model::SubjectType::I => NodeType::I,
        }
    }
}

/// Compact node key: 32 bytes for hex keys, `u64` for `user:id` / `post:id`
/// digits that round-trip, a shared string otherwise (model G5: keys are
/// lowercase subject strings).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeKey {
    Hex([u8; 32]),
    UserId(u64),
    PostId(u64),
    Str(Arc<str>),
}

fn round_trip_u64(digits: &str) -> Option<u64> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

impl NodeKey {
    /// Key for a subject value (normalized here, gap G5 fixed).
    pub fn parse(value: &str) -> NodeKey {
        let lower = dtp_model::subject::normalize_key(value);
        if let Some(bytes) = dtp_model::hex32(&lower) {
            return NodeKey::Hex(bytes);
        }
        if let Some(n) = lower.strip_prefix("user:id:").and_then(round_trip_u64) {
            return NodeKey::UserId(n);
        }
        if let Some(n) = lower.strip_prefix("post:id:").and_then(round_trip_u64) {
            return NodeKey::PostId(n);
        }
        NodeKey::Str(Arc::from(lower))
    }

    /// The lowercase subject value.
    pub fn value(&self) -> String {
        match self {
            NodeKey::Hex(b) => hex::encode(b),
            NodeKey::UserId(n) => format!("user:id:{n}"),
            NodeKey::PostId(n) => format!("post:id:{n}"),
            NodeKey::Str(s) => s.to_string(),
        }
    }

    /// `user:id:<digits>` accounts are the only keys that can bind.
    pub fn twitter_id(&self) -> Option<String> {
        match self {
            NodeKey::UserId(n) => Some(n.to_string()),
            NodeKey::Str(s) => dtp_model::subject::twitter_account_id(s).map(str::to_string),
            _ => None,
        }
    }

    pub fn estimated_bytes(&self) -> usize {
        match self {
            NodeKey::Hex(_) => 32,
            NodeKey::UserId(_) | NodeKey::PostId(_) => 8,
            NodeKey::Str(s) => s.len() + 16,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub key: NodeKey,
    pub ty: NodeType,
}

impl NodeInfo {
    /// Wire subject `{ type, value }`.
    pub fn subject(&self) -> dtp_model::Subject {
        let ty = match self.ty {
            NodeType::P => dtp_model::SubjectType::P,
            NodeType::E => dtp_model::SubjectType::E,
            NodeType::I => dtp_model::SubjectType::I,
        };
        dtp_model::Subject::new(ty, self.key.value())
    }

    pub fn is_bindable(&self) -> bool {
        self.ty == NodeType::I && self.key.twitter_id().is_some()
    }
}

/// Stable `NodeId`s, never reused or renumbered.
#[derive(Clone, Debug, Default)]
pub struct NodeTable {
    index: im::HashMap<NodeKey, NodeId>,
    info: im::Vector<NodeInfo>,
}

impl NodeTable {
    pub fn len(&self) -> usize {
        self.info.len()
    }

    pub fn is_empty(&self) -> bool {
        self.info.is_empty()
    }

    pub fn get(&self, key: &NodeKey) -> Option<NodeId> {
        self.index.get(key).copied()
    }

    pub fn info(&self, id: NodeId) -> &NodeInfo {
        &self.info[id as usize]
    }

    /// Returns the node for `key`, creating it; upgrades a hex node to `P`
    /// when `ty` is `P`.
    pub fn intern(&mut self, key: NodeKey, ty: NodeType) -> NodeId {
        if let Some(&id) = self.index.get(&key) {
            if ty == NodeType::P && self.info[id as usize].ty != NodeType::P {
                self.info[id as usize].ty = NodeType::P;
            }
            return id;
        }
        let id = self.info.len() as NodeId;
        assert!(
            id <= crate::entry::MAX_PACKED_NODE,
            "node table full for packed entries"
        );
        self.info.push_back(NodeInfo {
            key: key.clone(),
            ty,
        });
        self.index.insert(key, id);
        id
    }

    pub fn key_bytes(&self) -> usize {
        self.info.iter().map(|n| n.key.estimated_bytes()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(NodeKey::parse("user:id:42"), NodeKey::UserId(42));
        assert_eq!(NodeKey::parse("user:id:0"), NodeKey::UserId(0));
        assert!(matches!(NodeKey::parse("user:id:042"), NodeKey::Str(_)));
        assert_ne!(NodeKey::parse("user:id:042"), NodeKey::parse("user:id:42"));
        assert_eq!(NodeKey::parse("user:id:042").value(), "user:id:042");
        assert_eq!(NodeKey::parse("POST:ID:7"), NodeKey::PostId(7));
        let hex = "Ab".repeat(32);
        assert_eq!(NodeKey::parse(&hex).value(), hex.to_lowercase());
        assert_eq!(
            NodeKey::parse("user:id:99999999999999999999")
                .twitter_id()
                .as_deref(),
            Some("99999999999999999999")
        );
    }

    #[test]
    fn intern_upgrades_to_p() {
        let mut t = NodeTable::default();
        let k = NodeKey::parse(&"ab".repeat(32));
        let a = t.intern(k.clone(), NodeType::E);
        assert_eq!(t.info(a).ty, NodeType::E);
        let b = t.intern(k, NodeType::P);
        assert_eq!(a, b);
        assert_eq!(t.info(a).ty, NodeType::P);
    }
}
