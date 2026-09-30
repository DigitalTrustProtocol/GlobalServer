//! `dtp-resolve`: the resolver of `dtp-wot/1` over a `dtp-graph` snapshot.
//!
//! - [`walk`]: the exact walk (wot-model §6) with per-walk binding and
//!   guardrails;
//! - [`results`]: `TrustQueryResult` / `RatingQueryResult` mapping, batches;
//! - [`lookup`]: incoming / outgoing / counts / batch lookups, neighborhood;
//! - [`frontier`]: sync frontier and `graph.field`.

pub mod frontier;
pub mod lookup;
pub mod query;
pub mod results;
pub mod walk;

pub use query::{Limits, ParamError, ResolveQuery, merge_defaults};
pub use results::{ExecCtx, OwnInput, execute_batch, execute_rating, execute_trust};
pub use walk::{BindingMode, Budgets, OwnSource};

#[cfg(test)]
mod tests;
