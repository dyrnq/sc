//! Parameter file reader for `/etc/connectrc` and `~/.connectrc`.
//!
//! Mirrors `connect.c::read_parameter_file_1` (lines 723-773):
//!
//! - One `KEY = VALUE` per line.
//! - `#` starts a comment to end of line.
//! - Whitespace around KEY and VALUE is stripped.
//! - Empty lines and `#` lines are skipped.
//! - Unknown keys are reported via `error!` and skipped.
//! - Lines without `=` are reported as errors.
//!
//! After reading, `getparam(name)` looks up `name`: env var first, then the
//! value from the parameter file (if any). This is called from `auth.rs`
//! and elsewhere.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::Result;

/// Names of known parameters (matches connect.c `parameter_table`).
pub const KNOWN_KEYS: &[&str] = &[
    "socks_server",
    "socks5_server",
    "socks4_server",
    "socks_resolve",
    "socks5_resolve",
    "socks4_resolve",
    "socks5_user",
    "socks5_passwd",
    "socks5_password",
    "http_proxy",
    "http_proxy_user",
    "http_proxy_password",
    "connect_user",
    "connect_password",
    "ssh_askpass",
    "socks5_direct",
    "socks4_direct",
    "socks_direct",
    "http_direct",
    "connect_direct",
    "socks5_auth",
];

static TABLE: std::sync::LazyLock<Mutex<HashMap<String, String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Read the system `/etc/connectrc` then the user's `~/.connectrc`. Later
/// files overwrite earlier ones.
pub fn read_all() -> Result<()> {
    let mut table = TABLE.lock().unwrap();
    table.clear();

    // /etc/connectrc — skip silently on permission errors.
    if let Err(e) = read_one("/etc/connectrc", &mut table) {
        eprintln!("DEBUG: could not read /etc/connectrc: {e}");
    }

    // ~/.connectrc.
    if let Some(home) = home_dir() {
        let path = format!("{home}/.connectrc");
        if let Err(e) = read_one(&path, &mut table) {
            eprintln!("DEBUG: could not read {path}: {e}");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn home_dir() -> Option<String> {
    // SAFETY: getenv is async-signal-safe.
    unsafe {
        let ptr = libc::getenv(c"HOME".as_ptr());
        if ptr.is_null() {
            None
        } else {
            Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned())
        }
    }
}

#[cfg(not(unix))]
fn home_dir() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Read a single parameter file into `table`.
fn read_one(path: &str, table: &mut HashMap<String, String>) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    for (lineno, raw) in content.lines().enumerate() {
        parse_line(path, lineno + 1, raw, table);
    }
    Ok(())
}

/// Parse a single line into `table`. Per C semantics: trim leading
/// whitespace; if the first non-whitespace is `#` or the line is empty,
/// skip; otherwise split on the first `=`; trim KEY and VALUE.
fn parse_line(file: &str, lineno: usize, raw: &str, table: &mut HashMap<String, String>) {
    let trimmed_start = raw.trim_start();
    if trimmed_start.is_empty() || trimmed_start.starts_with('#') {
        return;
    }
    let Some(eq) = trimmed_start.find('=') else {
        tracing::error!("{file}:{lineno}: missing `='");
        return;
    };
    let key = trimmed_start[..eq].trim();
    let value = trimmed_start[eq + 1..].trim();
    if key.is_empty() {
        tracing::error!("{file}:{lineno}: empty key");
        return;
    }
    if !KNOWN_KEYS.contains(&key) {
        tracing::error!("{file}:{lineno}: unknown parameter `{key}'");
        return;
    }
    table.insert(key.to_string(), value.to_string());
    eprintln!("DEBUG: parameter `{key}' set to `{value}'");
}

/// Look up a parameter by name. Env var wins; fall back to the file
/// table.
pub fn getparam(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name)
        && !v.is_empty()
    {
        return Some(v);
    }
    TABLE.lock().unwrap().get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_basic() {
        let mut t = HashMap::new();
        parse_line("test", 1, "socks5_user = alice", &mut t);
        assert_eq!(t.get("socks5_user"), Some(&"alice".to_string()));
    }

    #[test]
    fn parse_line_comment_and_empty() {
        let mut t = HashMap::new();
        parse_line("test", 1, "# a comment", &mut t);
        parse_line("test", 2, "   ", &mut t);
        parse_line("test", 3, "   # indented comment", &mut t);
        assert!(t.is_empty());
    }

    #[test]
    fn parse_line_unknown_key() {
        let mut t = HashMap::new();
        parse_line("test", 1, "bogus_key = x", &mut t);
        assert!(t.is_empty());
    }

    #[test]
    fn parse_line_missing_eq() {
        let mut t = HashMap::new();
        parse_line("test", 1, "no equals sign", &mut t);
        assert!(t.is_empty());
    }
}
