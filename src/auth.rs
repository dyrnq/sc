//! Authentication: username/password lookup and password acquisition.
//!
//! Phase 4: env-var lookup only. Phase 5 adds `/dev/tty`, Phase 6 adds
//! `SSH_ASKPASS`.

use crate::config::ProxyMethod;
use crate::error::{Error, Result};

/// Look up the proxy username for the given method, considering env vars
/// (per-method → `CONNECT_USER` → `LOGNAME` → `USER`) and finally the system
/// account via `getlogin` (Unix only). Matches `connect.c` line 173-175.
pub fn determine_relay_user(method: ProxyMethod, socks_version: u8) -> Result<Option<String>> {
    const FALLBACK: &[&str] = &["LOGNAME", "USER"];
    let candidates: &[&str] = match method {
        ProxyMethod::Socks if socks_version == 5 => &["SOCKS5_USER", "SOCKS_USER", "CONNECT_USER"],
        ProxyMethod::Socks => &["SOCKS4_USER", "SOCKS_USER", "CONNECT_USER"],
        ProxyMethod::Http => &["HTTP_PROXY_USER", "CONNECT_USER"],
        ProxyMethod::Telnet | ProxyMethod::Direct | ProxyMethod::Undecided => &["CONNECT_USER"],
    };
    for name in candidates.iter().chain(FALLBACK) {
        if let Ok(v) = std::env::var(name)
            && !v.is_empty()
        {
            return Ok(Some(v));
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
        if let Ok(v) = std::env::var(name)
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    None
}

/// Read a password: env vars first, then `SSH_ASKPASS` (Phase 6), then
/// `/dev/tty` (Phase 5).
pub async fn readpass(prompt: &str, method: ProxyMethod, socks_version: u8) -> Result<String> {
    if let Some(p) = env_password(method, socks_version) {
        return Ok(p);
    }
    if let Ok(program) = std::env::var("SSH_ASKPASS") {
        #[cfg(unix)]
        {
            // On Unix, only use askpass when DISPLAY is set (matches
            // connect.c line 2058-2060).
            if std::env::var("DISPLAY").is_ok() {
                return ssh_askpass(prompt, &program).await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = program;
            return ssh_askpass(prompt, &program).await;
        }
    }
    crate::tty::tty_readpass(prompt)
}

/// Spawn `SSH_ASKPASS` with `prompt` as its argv[1], read the first line
/// of its stdout as the password.
async fn ssh_askpass(prompt: &str, program: &str) -> Result<String> {
    let output = tokio::process::Command::new(program)
        .arg(prompt)
        .output()
        .await
        .map_err(|e| Error::Auth(format!("SSH_ASKPASS spawn: {e}")))?;
    if !output.status.success() {
        return Err(Error::Auth(format!(
            "SSH_ASKPASS exited {:?}",
            output.status.code()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first = stdout.lines().next().unwrap_or("").to_string();
    Ok(first.trim_end_matches(['\r', '\n']).to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_askpass_invokes_program() {
        // Create a tiny shell script that echoes its argv[1] on stdout.
        let script = std::env::temp_dir().join("sc-askpass-test.sh");
        std::fs::write(&script, "#!/bin/sh\necho \"$1\"\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        unsafe {
            std::env::set_var("SSH_ASKPASS", &script);
        }
        let pass = ssh_askpass("prompt-text", script.to_str().unwrap())
            .await
            .unwrap();
        unsafe {
            std::env::remove_var("SSH_ASKPASS");
        }
        assert_eq!(pass, "prompt-text");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_askpass_strips_trailing_newline() {
        let script = std::env::temp_dir().join("sc-askpass-crlf-test.sh");
        std::fs::write(&script, "#!/bin/sh\nprintf '%s\\r\\n' \"$1\"\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let pass = ssh_askpass("secret-prompt", script.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(pass, "secret-prompt");
    }

    /// `LOGNAME` / `USER` are part of the fallback chain after the
    /// per-method env vars but before `getlogin()`. Mirror connect.c.
    /// Use a mutex so we don't race the parallel integration tests in
    /// `tests/socks5.rs` over `SOCKS5_PASSWD`.
    #[cfg(unix)]
    #[tokio::test]
    async fn determine_relay_user_falls_back_to_logname_user() {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // SAFETY: this test owns these env vars during its run.
        unsafe {
            std::env::remove_var("SOCKS5_USER");
            std::env::remove_var("SOCKS_USER");
            std::env::remove_var("SOCKS4_USER");
            std::env::remove_var("HTTP_PROXY_USER");
            std::env::remove_var("CONNECT_USER");
            std::env::set_var("LOGNAME", "from-logname");
            std::env::remove_var("USER");
        }
        let user = determine_relay_user(ProxyMethod::Socks, 5).unwrap();
        assert_eq!(user.as_deref(), Some("from-logname"));

        unsafe {
            std::env::remove_var("LOGNAME");
            std::env::set_var("USER", "from-user");
        }
        let user = determine_relay_user(ProxyMethod::Socks, 5).unwrap();
        assert_eq!(user.as_deref(), Some("from-user"));

        unsafe {
            std::env::remove_var("USER");
        }
    }
}
