//! End-to-end SOCKS5 integration tests.
//!
//! Spin up:
//! - a fake SOCKS5 server (loops: greeting → method select → optional USERPASS
//!   subneg → CONNECT → opens a real socket to the requested target → pumps
//!   bytes both ways)
//! - a loopback TCP echo server (the "destination")
//!
//! Then drive a real `sc::proxy::socks5::begin()` over a `TcpStream` connected
//! to the fake proxy, and assert a payload round-trips through the tunnel.
//!
//! Mirrors the shape of rusty_socks's `tests/socks5.rs` but on the client
//! side: the proxy here is a test double, the destination is a real echo.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sc::config::{Config, Family, ProxyMethod, ResolveMode};
use sc::proxy::socks5::begin;

/// Bind a loopback echo server and return its address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    addr
}

/// Spawn one fake-proxy task per incoming connection. Each connection runs the
/// full server-side SOCKS5 dance (greeting → optional USERPASS → CONNECT),
/// then bridges bytes to the requested target.
fn spawn_fake_proxy(listener: TcpListener, require_userpass: bool) {
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(run_fake_proxy_session(client, require_userpass));
        }
    });
}

async fn run_fake_proxy_session(
    mut client: TcpStream,
    require_userpass: bool,
) -> std::io::Result<()> {
    // ---- Greeting ----
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    client.read_exact(&mut methods).await?;

    // Pick the method: if userpass required, must be 0x02; else prefer 0x00.
    let chosen = if require_userpass {
        if !methods.contains(&0x02) {
            client.write_all(&[0x05, 0xFF]).await?;
            return Ok(());
        }
        0x02u8
    } else if methods.contains(&0x00) {
        0x00u8
    } else if methods.contains(&0x02) {
        0x02u8
    } else {
        client.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    };
    client.write_all(&[0x05, chosen]).await?;

    // ---- USERPASS subneg (if chosen) ----
    if chosen == 0x02 {
        let mut sub_hdr = [0u8; 2];
        client.read_exact(&mut sub_hdr).await?;
        if sub_hdr[0] != 0x01 {
            return Ok(());
        }
        let mut user = vec![0u8; sub_hdr[1] as usize];
        client.read_exact(&mut user).await?;
        let mut plen = [0u8; 1];
        client.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; plen[0] as usize];
        client.read_exact(&mut pass).await?;

        if user == b"bob" && pass == b"s3cret" {
            client.write_all(&[0x01, 0x00]).await?; // success
        } else {
            client.write_all(&[0x01, 0x01]).await?; // failure
            return Ok(());
        }
    }

    // ---- CONNECT ----
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        return Ok(());
    }

    let host_buf: Vec<u8> = match req[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            format!(
                "{}.{}.{}.{}",
                addr[0], addr[1], addr[2], addr[3]
            )
            .into_bytes()
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            name
        }
        0x04 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            // Toy "IPv6 loopback" stringification is enough — tests only use
            // IPv4 / DOMAINNAME in practice.
            std::net::Ipv6Addr::from(addr).to_string().into_bytes()
        }
        _ => return Ok(()),
    };
    let mut port_bytes = [0u8; 2];
    client.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    let host = String::from_utf8(host_buf).map_err(std::io::Error::other)?;
    let mut target = TcpStream::connect((host.as_str(), port)).await?;

    // ---- Reply: success, BND.ADDR=0.0.0.0:0 ----
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // ---- Pump bytes both ways ----
    let (mut cr, mut cw) = client.split();
    let (mut tr, mut tw) = target.split();
    let c2t = tokio::io::copy(&mut cr, &mut tw);
    let t2c = tokio::io::copy(&mut tr, &mut cw);
    tokio::select! {
        _ = c2t => {}
        _ = t2c => {}
    }
    Ok(())
}

fn socks5_config_noauth(proxy: SocketAddr, dest: SocketAddr) -> Config {
    let mut cfg = Config::default();
    cfg.relay_method = ProxyMethod::Socks;
    cfg.relay_host = Some(proxy.ip().to_string());
    cfg.relay_port = proxy.port();
    cfg.socks_version = 5;
    cfg.socks_resolve = ResolveMode::Remote;
    cfg.dest_host = dest.ip().to_string();
    cfg.dest_port = dest.port();
    cfg.family = Family::Any;
    cfg
}

fn socks5_config_userpass(proxy: SocketAddr, dest: SocketAddr) -> Config {
    let mut cfg = socks5_config_noauth(proxy, dest);
    cfg.relay_user = Some("bob".into());
    // SOCKS5_AUTH pins the offered methods; use that to opt in to USERPASS.
    cfg.socks5_auth = Some("userpass".into());
    cfg
}

async fn bind_loopback() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

/// Serializes env-var mutation across the four end-to-end tests. The SOCKS5
/// auth path consults `SOCKS5_PASSWD` (via `env_password`) and the no-auth
/// path inherits whatever was last set, so letting tests run in parallel
/// makes them non-hermetic. Holding this mutex is enough.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[tokio::test]
async fn end_to_end_noauth_round_trips_payload() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let echo_addr = spawn_echo().await;
    let proxy_listener = bind_loopback().await;
    let proxy_addr = proxy_listener.local_addr().unwrap();
    spawn_fake_proxy(proxy_listener, false);

    // Pre-empt any env-var fallbacks so readpass doesn't try to ask the tty.
    // SAFETY: this test is the only writer of these keys during its run.
    unsafe {
        std::env::set_var("SOCKS5_PASSWD", "ignored");
        std::env::remove_var("SSH_ASKPASS");
        std::env::remove_var("DISPLAY");
    }

    let body = async {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut cfg = socks5_config_noauth(proxy_addr, echo_addr);

        begin(&mut client, &mut cfg).await.expect("NOAUTH handshake should succeed");

        let payload = b"hello sc via NOAUTH";
        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed[..], &payload[..], "payload must round-trip");
    };

    timeout(Duration::from_secs(5), body)
        .await
        .expect("NOAUTH end-to-end flow should complete within 5s");
}

#[tokio::test]
async fn end_to_end_userpass_success_round_trips_payload() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let echo_addr = spawn_echo().await;
    let proxy_listener = bind_loopback().await;
    let proxy_addr = proxy_listener.local_addr().unwrap();
    spawn_fake_proxy(proxy_listener, true);

    // Bypass tty / askpass; make the env-supplied password the one we send.
    // SAFETY: this test is the only writer of these keys during its run.
    unsafe {
        std::env::set_var("SOCKS5_PASSWD", "s3cret");
        std::env::remove_var("SSH_ASKPASS");
        std::env::remove_var("DISPLAY");
    }

    let body = async {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut cfg = socks5_config_userpass(proxy_addr, echo_addr);

        begin(&mut client, &mut cfg)
            .await
            .expect("USERPASS handshake should succeed with valid credentials");

        let payload = b"hello sc via USERPASS";
        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed[..], &payload[..], "payload must round-trip after auth");
    };

    timeout(Duration::from_secs(5), body)
        .await
        .expect("USERPASS end-to-end flow should complete within 5s");
}

#[tokio::test]
async fn end_to_end_userpass_bad_credentials_are_rejected() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let echo_addr = spawn_echo().await;
    let proxy_listener = bind_loopback().await;
    let proxy_addr = proxy_listener.local_addr().unwrap();
    spawn_fake_proxy(proxy_listener, true);

    // Server expects "s3cret"; we hand it "wrong" so the auth must fail.
    // SAFETY: this test is the only writer of these keys during its run.
    unsafe {
        std::env::set_var("SOCKS5_PASSWD", "wrong");
        std::env::remove_var("SSH_ASKPASS");
        std::env::remove_var("DISPLAY");
    }

    let body = async {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut cfg = socks5_config_userpass(proxy_addr, echo_addr);

        let err = begin(&mut client, &mut cfg)
            .await
            .expect_err("bad credentials must be rejected");
        assert!(
            matches!(err, sc::error::Error::Socks5AuthFailed),
            "got {err:?}"
        );
    };

    timeout(Duration::from_secs(5), body)
        .await
        .expect("bad-credentials flow should complete within 5s");
}

#[tokio::test]
async fn end_to_end_no_acceptable_method_is_rejected() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Proxy requires userpass but the client offers only NOAUTH.
    let echo_addr = spawn_echo().await;
    let proxy_listener = bind_loopback().await;
    let proxy_addr = proxy_listener.local_addr().unwrap();
    spawn_fake_proxy(proxy_listener, true);

    unsafe {
        std::env::remove_var("SOCKS5_PASSWD");
        std::env::remove_var("SSH_ASKPASS");
        std::env::remove_var("DISPLAY");
    }

    let body = async {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut cfg = socks5_config_noauth(proxy_addr, echo_addr);
        // Override: only offer NOAUTH even though proxy needs USERPASS.
        cfg.socks5_auth = Some("none".into());

        let err = begin(&mut client, &mut cfg)
            .await
            .expect_err("no acceptable method must be rejected");
        assert!(
            matches!(err, sc::error::Error::Socks5NoAuth),
            "got {err:?}"
        );
    };

    timeout(Duration::from_secs(5), body)
        .await
        .expect("no-acceptable-method flow should complete within 5s");
}