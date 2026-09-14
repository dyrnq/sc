//! Authentication: username/password lookup and password acquisition.
//!
//! Phase 4: env-var lookup only. Phase 5 adds `/dev/tty`, Phase 6 adds
//! `SSH_ASKPASS`.

use crate::config::ProxyMethod;
use crate::error::{Error, Result};

/// Look up the proxy username for the given method, considering env vars
/// (per-method → `CONNECT_USER` → `LOGNAME` → `USER`) and finally the system
/// account via `getlogin` (Unix only). Matches `connect.c` line 173-175.
///
/// Proxy-specific keys are routed through `parameters::getparam` so
/// `.connectrc` / `/etc/connectrc` values work as a fallback below the
/// env vars. `LOGNAME` / `USER` stay as raw `env::var` since they
/// identify the *system* account, not a proxy configuration entry.
pub fn determine_relay_user(method: ProxyMethod, socks_version: u8) -> Result<Option<String>> {
    let candidates: &[&str] = match method {
        ProxyMethod::Socks if socks_version == 5 => &["SOCKS5_USER", "SOCKS_USER", "CONNECT_USER"],
        ProxyMethod::Socks => &["SOCKS4_USER", "SOCKS_USER", "CONNECT_USER"],
        ProxyMethod::Http => &["HTTP_PROXY_USER", "CONNECT_USER"],
        ProxyMethod::Telnet | ProxyMethod::Direct | ProxyMethod::Undecided => &["CONNECT_USER"],
    };
    // Proxy keys: env wins, fall back to connectrc.
    for name in candidates {
        if let Some(v) = crate::parameters::getparam(name)
            && !v.is_empty()
        {
            return Ok(Some(v));
        }
    }
    // System account: env only (LOGNAME/USER are POSIX, not proxy config).
    for name in ["LOGNAME", "USER"] {
        if let Ok(v) = std::env::var(name)
            && !v.is_empty()
        {
            return Ok(Some(v));
        }
    }
    // Fallback: system username.
    Ok(Some(system_username()))
}

/// Look up the proxy password from env vars, with `.connectrc` /
/// `/etc/connectrc` as fallback. Returns `None` if nothing is set; the
/// caller then falls back to `readpass`.
pub fn env_password(method: ProxyMethod, _socks_version: u8) -> Option<String> {
    let candidates: &[&str] = match method {
        ProxyMethod::Socks => &["SOCKS5_PASSWD", "SOCKS5_PASSWORD", "CONNECT_PASSWORD"],
        ProxyMethod::Http => &["HTTP_PROXY_PASSWORD", "CONNECT_PASSWORD"],
        _ => &["CONNECT_PASSWORD"],
    };
    for name in candidates {
        if let Some(v) = crate::parameters::getparam(name)
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

/// Spawn `SSH_ASKPASS` with `prompt` as its argv\[1\], read the first line
/// of its stdout as the password.
///
/// Retry on `ETXTBSY` (os error 26): the kernel returns this when exec
/// races with the inode's `MAP_DENYWRITE` release after a recent close,
/// and the race has been observed in CI (the test that writes the
/// script and immediately execs it hit it on shared ubuntu runners).
/// A short retry resolves it without changing the surface behaviour.
async fn ssh_askpass(prompt: &str, program: &str) -> Result<String> {
    const MAX_ATTEMPTS: u32 = 3;
    let mut attempt = 0;
    let output = loop {
        attempt += 1;
        match tokio::process::Command::new(program)
            .arg(prompt)
            .output()
            .await
        {
            Ok(o) => break o,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < MAX_ATTEMPTS => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            Err(e) => {
                return Err(Error::Auth(format!("SSH_ASKPASS spawn: {e}")));
            }
        }
    };
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

    /// Module-level mutex serialising tests that mutate the global
    /// `parameters::TABLE` and shared env vars (`SOCKS5_USER`,
    /// `SOCKS_USER`, `LOGNAME`, `USER`, etc.). Function-local `static
    /// LOCK` declarations are *not* shared across functions, so each
    /// test had its own lock and races were possible.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_askpass_invokes_program() {
        // Create a tiny shell script that echoes its argv[1] on stdout.
        // PID is part of the filename so concurrent CI runs on shared
        // runners don't collide. Mirrors the pattern in
        // `parameters::tests`.
        let script =
            std::env::temp_dir().join(format!("sc-askpass-{}-basic.sh", std::process::id()));
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
        let script =
            std::env::temp_dir().join(format!("sc-askpass-{}-crlf.sh", std::process::id()));
        std::fs::write(&script, "#!/bin/sh\nprintf '%s\\r\\n' \"$1\"\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let pass = ssh_askpass("secret-prompt", script.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(pass, "secret-prompt");
    }

    /// End-to-end for the new `getparam` wiring: when neither the
    /// per-method env var nor the `CONNECT_USER` fallback is set, a
    /// value pre-loaded into the file table (the same path `.connectrc`
    /// uses) must surface as the proxy username.
    #[cfg(unix)]
    #[tokio::test]
    async fn determine_relay_user_surfaces_connectrc_value() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // SAFETY: this test owns these env vars during its run.
        unsafe {
            std::env::remove_var("SOCKS5_USER");
            std::env::remove_var("SOCKS_USER");
            std::env::remove_var("CONNECT_USER");
            std::env::remove_var("LOGNAME");
            std::env::remove_var("USER");
        }
        // Pre-populate the file table with a connectrc-style value
        // for SOCKS5_USER. `getparam` will fall back to it.
        let prev = crate::parameters::_insert_for_test("SOCKS5_USER", "from-connectrc");

        let user = determine_relay_user(ProxyMethod::Socks, 5).unwrap();
        assert_eq!(user.as_deref(), Some("from-connectrc"));

        // Restore prior TABLE entry.
        let mut t = crate::parameters::TABLE.lock().unwrap();
        match prev {
            Some(v) => {
                t.insert("SOCKS5_USER".into(), v);
            }
            None => {
                t.remove("SOCKS5_USER");
            }
        }
    }

    /// `LOGNAME` / `USER` are part of the fallback chain after the
    /// per-method env vars but before `getlogin()`. Mirror connect.c.
    /// Shares `ENV_LOCK` with the connectrc test above so they cannot
    /// race on the same `SOCKS5_USER` / `LOGNAME` / `USER` state.
    #[cfg(unix)]
    #[tokio::test]
    async fn determine_relay_user_falls_back_to_logname_user() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

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
