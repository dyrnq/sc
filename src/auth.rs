//! Authentication: username/password lookup and password acquisition.
//!
//! Phase 4: env-var lookup only. Phase 5 adds `/dev/tty`, Phase 6 adds
//! `SSH_ASKPASS`.

use crate::config::ProxyMethod;
use crate::error::{Error, Result};

/// Look up the proxy username for the given method, considering env vars
/// (`SOCKS5_USER`/`SOCKS4_USER`/`SOCKS_USER`/`HTTP_PROXY_USER`/`CONNECT_USER`)
/// and finally the system account via `getlogin` (Unix only).
pub fn determine_relay_user(method: ProxyMethod, socks_version: u8) -> Result<Option<String>> {
    let candidates: &[&str] = match method {
        ProxyMethod::Socks if socks_version == 5 => {
            &["SOCKS5_USER", "SOCKS_USER", "CONNECT_USER"]
        }
        ProxyMethod::Socks => &["SOCKS4_USER", "SOCKS_USER", "CONNECT_USER"],
        ProxyMethod::Http => &["HTTP_PROXY_USER", "CONNECT_USER"],
        ProxyMethod::Telnet | ProxyMethod::Direct | ProxyMethod::Undecided => &["CONNECT_USER"],
    };
    for name in candidates {
        if let Ok(v) = std::env::var(name) {
            if !v.is_empty() {
                return Ok(Some(v));
            }
        }
    }
    // Fallback: system username.
    Ok(Some(system_username()))
}

/// Look up the proxy password from env vars. Returns `None` if no env var
/// is set; the caller then falls back to `readpass`.
pub fn env_password(method: ProxyMethod, _socks_version: u8) -> Option<String> {
    let candidates: &[&str] = match method {
        ProxyMethod::Socks => &["SOCKS5_PASSWD", "SOCKS5_PASSWORD", "CONNECT_PASSWORD"],
        ProxyMethod::Http => &["HTTP_PROXY_PASSWORD", "CONNECT_PASSWORD"],
        _ => &["CONNECT_PASSWORD"],
    };
    for name in candidates {
        if let Ok(v) = std::env::var(name) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Read a password: env vars first, then `SSH_ASKPASS` (Phase 6), then
/// `/dev/tty` (Phase 5). Phase 4 only handles env vars; the others return
/// `Todo`.
pub fn readpass(prompt: &str, method: ProxyMethod, socks_version: u8) -> Result<String> {
    if let Some(p) = env_password(method, socks_version) {
        return Ok(p);
    }
    if std::env::var("SSH_ASKPASS").is_ok() {
        return Err(Error::Todo("readpass via SSH_ASKPASS (Phase 6)"));
    }
    let _ = prompt;
    Err(Error::Todo("readpass via /dev/tty (Phase 5)"))
}

#[cfg(unix)]
fn system_username() -> String {
    // SAFETY: `getlogin` is async-signal-safe and only reads from utmp.
    unsafe {
        let ptr = libc::getlogin();
        if ptr.is_null() {
            return String::from("root");
        }
        let cstr = std::ffi::CStr::from_ptr(ptr);
        cstr.to_string_lossy().into_owned()
    }
}

#[cfg(not(unix))]
fn system_username() -> String {
    String::from("user")
}
