//! Monotonic connection-ID counter used as a tracing span field.
//!
//! Every connection `sc` handles — whether via `-p`/`-P` listen or a
//! one-shot stdin/stdout relay — enters a `connection` span carrying
//! the next integer from [`ConnectionId::next`]. Every event emitted
//! inside that span (and inside its child `#[tracing::instrument]`
//! spans on `relay` / `proxy::handshake`) automatically inherits the
//! `conn_id` field, so concurrent connections can be told apart in
//! production logs without threading the ID through every call site.
//!
//! IDs are dense starting at 0, atomic, and never reused in a process
//! lifetime. For an `sc` invocation that lives for a few minutes the
//! space cost is irrelevant.

use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque, dense, process-unique connection identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

static NEXT: AtomicU64 = AtomicU64::new(0);

impl ConnectionId {
    /// Allocate the next ID. Thread-safe; concurrent callers get
    /// distinct values with no contention hot path.
    pub fn next() -> Self {
        ConnectionId(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Enter a `connection` span carrying `conn_id = id.0` and return its
/// `EnteredSpan` guard. Drop the guard (typically at end of scope) to
/// leave the span. Nested `#[tracing::instrument]` spans become
/// children and inherit the field.
pub fn span(id: ConnectionId) -> tracing::span::EnteredSpan {
    tracing::info_span!("connection", conn_id = id.0).entered()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids_are_unique_and_dense() {
        let a = ConnectionId::next();
        let b = ConnectionId::next();
        let c = ConnectionId::next();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        assert_eq!(b.0, a.0 + 1);
        assert_eq!(c.0, b.0 + 1);
    }
}
