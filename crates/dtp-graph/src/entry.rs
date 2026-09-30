//! Packed adjacency entries: `node:28 | value:2 | window:1 | siblings:1`
//! (graph-engine.md § Packed adjacency).

use crate::NodeId;

/// Largest node id a packed `u32` entry can hold.
pub const MAX_PACKED_NODE: NodeId = (1 << 28) - 1;

const VALUE_SHIFT: u32 = 28;
const WINDOW_BIT: u32 = 1 << 30;
const SIBLINGS_BIT: u32 = 1 << 31;

/// Two-bit value code for kind 32009: `0` Neutral, `1` Trust, `2` Distrust.
/// Kind 32014 entries store `0` (the score lives in the cold columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Entry(pub u32);

impl Entry {
    /// Packs an entry. Panics if `node` exceeds 28 bits (the next base
    /// rebuild switches to `u64` entries; not implemented yet).
    pub fn pack(node: NodeId, value_code: u8, window: bool, siblings: bool) -> Entry {
        assert!(
            node <= MAX_PACKED_NODE,
            "node id exceeds packed entry range"
        );
        debug_assert!(value_code < 3);
        let mut raw = node | (u32::from(value_code) << VALUE_SHIFT);
        if window {
            raw |= WINDOW_BIT;
        }
        if siblings {
            raw |= SIBLINGS_BIT;
        }
        Entry(raw)
    }

    pub fn node(self) -> NodeId {
        self.0 & MAX_PACKED_NODE
    }

    pub fn value_code(self) -> u8 {
        ((self.0 >> VALUE_SHIFT) & 0b11) as u8
    }

    /// Kind 32009 trust value.
    pub fn trust_value(self) -> i8 {
        match self.value_code() {
            1 => 1,
            2 => -1,
            _ => 0,
        }
    }

    /// The record has an `x` / `y` window: check activity in the cold columns.
    pub fn has_window(self) -> bool {
        self.0 & WINDOW_BIT != 0
    }

    /// The author has several entries to this node in this bucket.
    pub fn has_siblings(self) -> bool {
        self.0 & SIBLINGS_BIT != 0
    }

    pub fn with_siblings(self, siblings: bool) -> Entry {
        if siblings {
            Entry(self.0 | SIBLINGS_BIT)
        } else {
            Entry(self.0 & !SIBLINGS_BIT)
        }
    }
}

/// Value code for a kind 32009 value.
pub fn trust_code(value: i8) -> u8 {
    match value {
        1 => 1,
        -1 => 2,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let e = Entry::pack(MAX_PACKED_NODE, 2, true, false);
        assert_eq!(e.node(), MAX_PACKED_NODE);
        assert_eq!(e.trust_value(), -1);
        assert!(e.has_window());
        assert!(!e.has_siblings());
        let s = e.with_siblings(true);
        assert!(s.has_siblings());
        assert_eq!(s.node(), MAX_PACKED_NODE);
        assert_eq!(s.with_siblings(false), e);
        assert_eq!(Entry::pack(7, trust_code(1), false, false).trust_value(), 1);
        assert_eq!(Entry::pack(7, trust_code(0), false, false).trust_value(), 0);
    }

    #[test]
    #[should_panic]
    fn node_overflow_panics() {
        Entry::pack(MAX_PACKED_NODE + 1, 0, false, false);
    }
}
