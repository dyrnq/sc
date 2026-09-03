//! Local TCP listen socket for `-p` / `-P` modes.
//!
//! Implemented in Phase 9. Currently a placeholder.

use crate::config::Config;
use crate::error::Result;

/// Accept a single local TCP connection and run the relay loop.
///
/// `hold_session == true` causes the remote socket to be kept across accepts.
pub async fn accept_loop(_cfg: &Config) -> Result<()> {
    Err(crate::error::Error::Todo("listen mode (Phase 9)"))
}
