//! Typed error conditions for the nuvek-core boundary.
//!
//! Most fallible functions return `anyhow::Result` for ergonomic context chaining, but a
//! few conditions are load-bearing enough that callers need to match on them (a read-only
//! guard rejection, a bounded-operation timeout). Those are `thiserror` variants here and
//! flow through `anyhow` via `?` when they don't need to be matched.

use std::time::Duration;

/// Errors that callers may want to distinguish programmatically.
#[derive(Debug, thiserror::Error)]
pub enum NuvekError {
    /// A bounded operation exceeded its deadline.
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    /// A Cypher string containing a write clause was passed to a read-only query path.
    /// The graph is a derived projection; writes go through the sync tooling only.
    #[error("refusing to execute a write clause on the read-only graph: found `{0}`")]
    WriteClauseRejected(String),
}
