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
/// files overwrite earlier ones. Per-file failures are traced at debug
/// level and skipped — this call is infallible and intended to run
/// unconditionally at startup.
pub fn read_all() {
    let mut table = TABLE.lock().unwrap();
    table.clear();

    // /etc/connectrc — skip silently on permission errors.
    if let Err(e) = read_one("/etc/connectrc", &mut table) {
        tracing::debug!("/etc/connectrc: {e}");
    }

    // ~/.connectrc.
    if let Some(home) = home_dir() {
        let path = format!("{home}/.connectrc");
        if let Err(e) = read_one(&path, &mut table) {
            tracing::debug!("{path}: {e}");
        }
    }
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
    tracing::debug!("parameter `{key}' set to `{value}'");
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

    /// `getparam` is env-first, so when both are set the env value wins.
    /// Pin the precedence so a future refactor can't silently flip it.
    #[test]
    fn getparam_env_wins_over_file() {
        // SAFETY: this test owns these env vars during its run.
        unsafe {
            std::env::set_var("socks4_resolve", "from-env");
        }
        let prev = TABLE
            .lock()
            .unwrap()
            .insert("socks4_resolve".into(), "from-file".into());

        assert_eq!(getparam("socks4_resolve").as_deref(), Some("from-env"));

        // Cleanup.
        unsafe {
            std::env::remove_var("socks4_resolve");
        }
        let mut t = TABLE.lock().unwrap();
        match prev {
            Some(v) => {
                t.insert("socks4_resolve".into(), v);
            }
            None => {
                t.remove("socks4_resolve");
            }
        }
    }

    /// When the env var is unset (or empty) `getparam` falls back to the
    /// value that `read_all` populated from `.connectrc`.
    #[test]
    fn getparam_falls_back_to_file_table() {
        // SAFETY: this test owns these env vars during its run.
        unsafe {
            std::env::remove_var("connect_direct");
        }
        let prev = TABLE
            .lock()
            .unwrap()
            .insert("connect_direct".into(), "from-file".into());

        assert_eq!(getparam("connect_direct").as_deref(), Some("from-file"));

        // Cleanup.
        let mut t = TABLE.lock().unwrap();
        match prev {
            Some(v) => {
                t.insert("connect_direct".into(), v);
            }
            None => {
                t.remove("connect_direct");
            }
        }
    }

    /// An empty env var should NOT shadow a real file-table value
    /// (`getparam` treats empty env vars as unset, matching
    /// `connect.c::getparam` semantics).
    #[test]
    fn getparam_empty_env_does_not_shadow_file_value() {
        // SAFETY: this test owns these env vars during its run.
        unsafe {
            std::env::set_var("socks5_resolve", "");
        }
        let prev = TABLE
            .lock()
            .unwrap()
            .insert("socks5_resolve".into(), "from-file".into());

        assert_eq!(getparam("socks5_resolve").as_deref(), Some("from-file"));

        // Cleanup.
        unsafe {
            std::env::remove_var("socks5_resolve");
        }
        let mut t = TABLE.lock().unwrap();
        match prev {
            Some(v) => {
                t.insert("socks5_resolve".into(), v);
            }
            None => {
                t.remove("socks5_resolve");
            }
        }
    }

    /// End-to-end: `read_all` reads `/etc/connectrc` then a temp
    /// `~/.connectrc`, and `getparam` surfaces the file value when env
    /// is unset. Uses keys unique to this test to avoid races with the
    /// parallel unit tests that mutate `TABLE` / env directly.
    #[cfg(unix)]
    #[test]
    fn read_all_loads_connectrc_end_to_end() {
        let dir = std::env::temp_dir().join(format!("sc-connectrc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rc = dir.join(".connectrc");
        // Use keys that no other test touches and that are in KNOWN_KEYS.
        std::fs::write(
            &rc,
            "http_proxy = proxy.corp:8080\nssh_askpass = /usr/bin/ssh-askpass\n",
        )
        .unwrap();

        let prev_home = std::env::var("HOME").ok();
        // SAFETY: this test owns HOME during its run.
        unsafe {
            std::env::set_var("HOME", &dir);
        }

        // Snapshot TABLE entries we'll touch, so we can restore them.
        let prev_http_proxy = TABLE.lock().unwrap().remove("http_proxy");
        let prev_ssh_askpass = TABLE.lock().unwrap().remove("ssh_askpass");
        // SAFETY: this test owns these env vars during its run.
        unsafe {
            std::env::remove_var("http_proxy");
            std::env::remove_var("SSH_ASKPASS");
        }

        read_all();

        assert_eq!(
            getparam("http_proxy").as_deref(),
            Some("proxy.corp:8080"),
            "http_proxy from .connectrc should be visible via getparam"
        );
        assert_eq!(
            getparam("ssh_askpass").as_deref(),
            Some("/usr/bin/ssh-askpass"),
            "ssh_askpass from .connectrc should be visible via getparam"
        );

        // Restore HOME and TABLE.
        // SAFETY: restoring prior HOME for the test process.
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let mut t = TABLE.lock().unwrap();
        if let Some(v) = prev_http_proxy {
            t.insert("http_proxy".into(), v);
        }
        if let Some(v) = prev_ssh_askpass {
            t.insert("ssh_askpass".into(), v);
        }

        // Best-effort cleanup of the temp dir.
        let _ = std::fs::remove_file(&rc);
        let _ = std::fs::remove_dir(&dir);
    }
}
