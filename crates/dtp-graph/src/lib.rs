//! `dtp-graph`: the graph store of the Global Server (graph-engine.md).
//!
//! Stable `u32` node ids, packed `u32` adjacency entries in three CSRs
//! (`trust_in`, `trust_out`, `rating_in`) grouped by context bucket, an
//! immutable base tier plus a persistent RAM delta with dead bits, slot
//! winners with NIP-09 floors, and the identity-binding indexes (`hints`,
//! `hinted_as`, `claims`). Binds themselves are decided per walk in
//! `dtp-resolve`.
//!
//! The base CSR is plain `Vec<u32>` arrays in the final on-disk layout;
//! memory-mapped tiered segment files are the next increment (see PLAN.md).

pub mod contexts;
pub mod csr;
pub mod entry;
pub mod graph;
pub mod nodes;

pub use contexts::{BucketInfo, ContextTable};
pub use entry::Entry;
pub use graph::{
    Adj, ApplyOutcome, ClaimSlot, DKey, DeletionOutcome, Display, EdgeCols, Graph, GraphStats,
    SlotKey, SlotState, Winner,
};
pub use nodes::{NodeInfo, NodeKey, NodeType};

pub type NodeId = u32;
pub type EdgeId = u32;
pub type BucketId = u32;

#[cfg(test)]
mod tests;
