//! Bypass-proxy table (CIDR + domain entries).
//!
//! Implemented in Phase 10.

use crate::error::Result;

/// Initialise the bypass table from environment variables and the `-D` flag.
pub fn initialize(_entries: &[String], _auto_local: bool) -> Result<()> {
    Ok(())
}

/// Decide whether `host` should bypass the proxy and connect directly.
pub fn check_direct(_host: &str) -> bool {
    false
}
