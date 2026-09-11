//! Proxy method dispatch.
//!
//! [`open_through_proxy`] is the single entry point both the one-shot
//! stdio path (`main.rs`) and the listen-mode path (`listen.rs`) use to
//! connect to a destination through the configured proxy. It honours
//! `cfg.connect_timeout` for the initial TCP connect (the `-w` flag), so
//! the timeout fires in either path.

pub mod direct;
pub mod http;
pub mod socks4;
pub mod socks5;
pub mod telnet;
pub mod util;

use std::time::Duration;

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::{Error, Result};

/// Connect to `relay_host:relay_port` (the proxy server). For DIRECT mode
/// the relay host is unset and this returns an error.
pub async fn connect_relay(cfg: &Config) -> Result<TcpStream> {
    let host = cfg
        .relay_host
        .as_deref()
        .ok_or_else(|| Error::Config("no relay host set".into()))?;
    let addrs = crate::resolve::resolve_host(host, cfg.relay_port, cfg.family).await?;
    let stream = TcpStream::connect(addrs.as_slice()).await?;
    Ok(stream)
}

/// Wrap a connect future with `secs` seconds of timeout. `secs == 0`
/// disables the wrapper and the inner future runs to completion.
///
/// Mirrors `connect.c`'s SIGALRM-based connect timeout. Lives here
/// (not in `main.rs`) so the listen-mode path can share it.
pub async fn connect_with_timeout<F, T>(secs: u32, f: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    if secs > 0 {
        match tokio::time::timeout(Duration::from_secs(secs as u64), f).await {
            Ok(r) => r,
            Err(_) => Err(Error::Config(format!("connect timeout after {secs}s"))),
        }
    } else {
        f.await
    }
}

/// Connect to the destination through the configured proxy method, running
/// the protocol handshake to the end. Returns a `TcpStream` ready to hand
/// to `relay::relay*`.
///
/// This is the single dispatcher for both the stdio path and the listen
/// path, so `cfg.connect_timeout` (the `-w` flag) fires consistently in
/// either path. Previously the listen path bypassed this timeout
/// altogether — the connect future ran without a wrapper and a black-
/// holed proxy would hang until the kernel's TCP retransmit budget
/// (~60s) was exhausted.
#[tracing::instrument(skip(cfg), fields(?cfg.relay_method, socks_version = cfg.socks_version))]
pub async fn open_through_proxy(cfg: &Config) -> Result<TcpStream> {
    use crate::config::ProxyMethod;

    let mut cfg = cfg.clone();
    let mut stream = connect_with_timeout(cfg.connect_timeout, async {
        match cfg.relay_method {
            ProxyMethod::Direct => direct::connect(&cfg).await,
            ProxyMethod::Socks => connect_relay(&cfg).await,
            ProxyMethod::Http => {
                // HTTP has its own 302-redirect / 401-407 retry loop;
                // each new CONNECT attempt re-enters connect_relay.
                let mut s = connect_relay(&cfg).await?;
                loop {
                    match http::begin(&mut s, &mut cfg).await? {
                        http::HttpStart::Ok => break Ok(s),
                        http::HttpStart::Retry => {
                            drop(s);
                            s = connect_relay(&cfg).await?;
                        }
                    }
                }
            }
            ProxyMethod::Telnet => {
                let mut s = connect_relay(&cfg).await?;
                telnet::begin(&mut s, &cfg).await?;
                Ok(s)
            }
            ProxyMethod::Undecided => Err(Error::Config("no proxy method".into())),
        }
    })
    .await?;

    // SOCKS handshake runs after the relay-socket TCP connect; HTTP and
    // TELNET already completed their handshake inline above.
    if matches!(cfg.relay_method, ProxyMethod::Socks) {
        handshake(&mut stream, &mut cfg).await?;
    }
    Ok(stream)
}

/// Run the proxy handshake on an already-connected TCP stream.
///
/// HTTP CONNECT has its own retry loop (302 / 401 / 407), so callers
/// handling HTTP should dispatch `http::begin` directly rather than going
/// through this dispatcher. (Direct callers of this function typically
/// have only the SOCKS / TELNET / Direct methods left to handle after
/// their own HTTP loop.)
#[tracing::instrument(skip(stream), fields(?cfg.relay_method, socks_version = cfg.socks_version))]
pub async fn handshake(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    use crate::config::ProxyMethod;
    match cfg.relay_method {
        ProxyMethod::Direct | ProxyMethod::Undecided | ProxyMethod::Http => Ok(()),
        ProxyMethod::Socks => {
            if cfg.socks_version == 5 {
                socks5::begin(stream, cfg).await
            } else {
                socks4::begin(stream, cfg).await
            }
        }
        ProxyMethod::Telnet => telnet::begin(stream, cfg).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::net::TcpListener;

    /// `connect_with_timeout(1, hang_forever())` must surface a typed
    /// `Config` timeout error within a couple of seconds, not wait for
    /// the kernel's TCP retransmit budget.
    #[tokio::test]
    async fn connect_with_timeout_fires_on_hanging_future() {
        async fn hang_forever() -> Result<TcpStream> {
            std::future::pending().await
        }
        let start = Instant::now();
        let result = connect_with_timeout(1, hang_forever()).await;
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(Error::Config(ref m)) if m == "connect timeout after 1s"),
            "got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "timeout didn't fire in time: {elapsed:?}"
        );
    }

    /// `secs == 0` disables the wrapper entirely — the inner future's
    /// `Result` is passed through unchanged. Verified by returning a
    /// sentinel error from the inner future and asserting it survives.
    #[tokio::test]
    async fn connect_with_timeout_zero_passes_through() {
        async fn quick_err() -> Result<TcpStream> {
            Err(Error::Config("sentinel".into()))
        }
        let result = connect_with_timeout(0, quick_err()).await;
        assert!(
            matches!(result, Err(Error::Config(ref m)) if m == "sentinel"),
            "got {result:?}"
        );
    }

    /// `open_through_proxy` in Direct mode reaches a bound TCP listener
    /// and returns a usable stream. This pins the dispatch + connect
    /// wiring; the SOCKS / HTTP / TELNET paths are exercised by their
    /// own module tests and the integration tests in `tests/socks5.rs`.
    #[tokio::test]
    async fn open_through_proxy_direct_mode_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Drain accepts so the test can exit cleanly.
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 16];
                    let _ = tokio::io::AsyncReadExt::read(&mut s, &mut buf).await;
                });
            }
        });

        let cfg = Config {
            relay_method: crate::config::ProxyMethod::Direct,
            dest_host: "127.0.0.1".into(),
            dest_port: port,
            connect_timeout: 0,
            ..Config::default()
        };
        let stream = open_through_proxy(&cfg)
            .await
            .expect("direct mode should reach the bound listener");
        drop(stream);
    }

    /// `open_through_proxy` in Direct mode against a black-holed port
    /// must return within `connect_timeout + a small slack`. We bind a
    /// listener and immediately drop it so the kernel sends RST on the
    /// next SYN — but that's instant, not what we want to test. Instead
    /// we point at `127.0.0.1:<unbound-port>` which gets a fast
    /// `ECONNREFUSED`; verify the wrapper DOES surface that error (it
    /// should NOT time out, because the connect failed immediately).
    #[tokio::test]
    async fn open_through_proxy_returns_fast_failure_when_kernel_rsts() {
        // Bind + drop so the port is known-unbound (loopback RST).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let cfg = Config {
            relay_method: crate::config::ProxyMethod::Direct,
            dest_host: "127.0.0.1".into(),
            dest_port: port,
            connect_timeout: 5,
            ..Config::default()
        };
        let start = Instant::now();
        let result = open_through_proxy(&cfg).await;
        let elapsed = start.elapsed();
        assert!(result.is_err(), "expected ECONNREFUSED-style error");
        assert!(
            elapsed < Duration::from_secs(3),
            "kernel RST should be fast; got {elapsed:?}"
        );
    }
}
