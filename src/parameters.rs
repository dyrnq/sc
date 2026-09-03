//! Parameter file reader for `/etc/connectrc` and `~/.connectrc`.
//!
//! Implemented in Phase 11. Currently a placeholder that only checks `getenv`.

use std::env;

/// Look up a parameter. Env vars always win.
pub fn getparam(name: &str) -> Option<String> {
    env::var(name).ok()
}

/// Pre-load `/etc/connectrc` and `~/.connectrc` into the parameter table.
/// (No-op until Phase 11.)
pub fn read_parameter_file() {
    // TODO(Phase 11): parse /etc/connectrc and ~/.connectrc into a static table.
}
