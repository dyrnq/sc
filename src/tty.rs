//! Terminal no-echo password input.
//!
//! Implemented in Phase 5. Currently a placeholder.

use crate::error::Result;

/// Read a line from `/dev/tty` with echo disabled.
///
/// Unix: uses `nix::termios` to clear `ECHO|ECHONL|...` and restore on exit.
/// Windows: uses `SetConsoleMode` to clear `ENABLE_ECHO_INPUT`.
pub fn tty_readpass(_prompt: &str) -> Result<String> {
    Err(crate::error::Error::Todo("tty_readpass (Phase 5)"))
}
