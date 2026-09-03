//! Authentication: username/password lookup and password acquisition.
//!
//! Filled in by Phases 4–6. Currently a placeholder.

use crate::error::Result;

/// Returns the proxy username for the given method, or `None` if not set.
pub fn determine_relay_user() -> Result<Option<String>> {
    Ok(None)
}

/// Read a password: env vars first, then `SSH_ASKPASS`, then `/dev/tty`.
///
/// Implemented in Phase 4 (env-only), Phase 5 (TTY), Phase 6 (askpass).
pub fn readpass(_prompt: &str) -> Result<String> {
    Err(crate::error::Error::Todo("readpass (Phase 4–6)"))
}
