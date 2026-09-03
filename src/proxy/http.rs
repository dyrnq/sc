//! HTTP CONNECT handshake (Phase 3: no auth; Phase 4+: auth + retry).
//!
//! Request: `CONNECT host:port HTTP/1.0\r\n[Proxy-Authorization: Basic ...\r\n]\r\n`
//! Response status codes:
//! - 200 → success
//! - 302 → parse `Location:`, update `relay_host`/`relay_port`, return `Retry`
//! - 401 / 407 → Basic challenge (Phase 4); set `proxy_auth`, return `Retry`
//! - other → `Error::HttpStatus(code)`
//!
//! The caller (main) is responsible for reconnecting on `Retry`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Config, ProxyAuthType};
use crate::error::{Error, Result};

/// Outcome of a single HTTP CONNECT attempt.
#[derive(Debug)]
pub enum HttpStart {
    /// Tunnel is established; caller should now run the relay loop.
    Ok,
    /// The proxy told us to try a different host/port or to authenticate.
    /// Caller reconnects (with the updated `cfg`).
    Retry,
}

/// Run one HTTP CONNECT attempt. Returns `Ok` to relay, `Retry` to
/// reconnect, or `Err` on hard failure.
///
/// `cfg.proxy_auth` controls whether `Proxy-Authorization` is sent.
#[tracing::instrument(skip(stream), fields(?cfg.proxy_auth))]
pub async fn begin(stream: &mut TcpStream, cfg: &mut Config) -> Result<HttpStart> {
    send_request(stream, cfg).await?;
    let status = read_status_line(stream).await?;
    match status {
        200 => {
            drain_headers(stream).await?;
            Ok(HttpStart::Ok)
        }
        302 => {
            parse_location_for_redirect(stream, cfg).await?;
            Ok(HttpStart::Retry)
        }
        401 | 407 => {
            // If we already tried with auth, fail.
            if !matches!(cfg.proxy_auth, ProxyAuthType::None) {
                return Err(Error::Http("authentication failed"));
            }
            parse_auth_challenge(stream).await?;
            Ok(HttpStart::Retry)
        }
        other => Err(Error::HttpStatus(other)),
    }
}

async fn send_request(stream: &mut TcpStream, cfg: &Config) -> Result<()> {
    let mut req = format!("CONNECT {}:{} HTTP/1.0\r\n", cfg.dest_host, cfg.dest_port);
    if matches!(cfg.proxy_auth, ProxyAuthType::Basic) {
        let user = cfg
            .relay_user
            .as_deref()
            .ok_or(Error::Auth("missing proxy user".into()))?;
        let pass = std::env::var("HTTP_PROXY_PASSWORD")
            .or_else(|_| std::env::var("CONNECT_PASSWORD"))
            .map_err(|_| Error::Auth("no proxy password in env".into()))?;
        let creds = format!("{user}:{pass}");
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
        req.push_str(&format!("Proxy-Authorization: Basic {b64}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    Ok(())
}

/// Read one CRLF-terminated line into `buf`. Returns when `\n` is seen or
/// when EOF is reached. `buf` is cleared first.
async fn read_line<R: AsyncRead + Unpin>(r: &mut R, buf: &mut String) -> Result<()> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            // EOF. If we already accumulated some chars, treat as a line;
            // otherwise it's truly empty.
            return Ok(());
        }
        if byte[0] == b'\n' {
            return Ok(());
        }
        if byte[0] != b'\r' {
            buf.push(byte[0] as char);
        }
    }
}

async fn read_status_line(stream: &mut TcpStream) -> Result<u16> {
    let mut line = String::new();
    read_line(stream, &mut line).await?;
    let code: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(Error::Http("bad status line"))?;
    Ok(code)
}

async fn drain_headers(stream: &mut TcpStream) -> Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        read_line(stream, &mut line).await?;
        if line.is_empty() {
            return Ok(());
        }
    }
}

async fn parse_location_for_redirect(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    let mut line = String::new();
    let mut new_host: Option<String> = None;
    let mut new_port: u16 = 0;
    loop {
        line.clear();
        read_line(stream, &mut line).await?;
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("location: ") {
            // C uses cut_token("//") then cut_token("/") then cut_token(":")
            // on `//host:port/...`. Replicate with simple string ops.
            let raw = &line[line.len() - rest.len()..];
            let raw = raw.trim();
            let after_slashes = raw.strip_prefix("//").unwrap_or(raw);
            let host_port = after_slashes.split('/').next().unwrap_or("");
            if let Some(colon) = host_port.rfind(':') {
                new_host = Some(host_port[..colon].to_string());
                if let Ok(p) = host_port[colon + 1..].parse::<u16>() {
                    new_port = p;
                }
            } else {
                new_host = Some(host_port.to_string());
            }
        }
    }
    if let Some(h) = new_host {
        cfg.relay_host = Some(h);
    }
    if new_port > 0 {
        cfg.relay_port = new_port;
    }
    Ok(())
}

async fn parse_auth_challenge(stream: &mut TcpStream) -> Result<()> {
    let mut line = String::new();
    let mut found = false;
    loop {
        line.clear();
        read_line(stream, &mut line).await?;
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if (lower.starts_with("www-authenticate:") || lower.starts_with("proxy-authenticate:"))
            && lower.contains("basic")
        {
            found = true;
        }
    }
    if !found {
        return Err(Error::Http("no Basic auth in challenge"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn read_line_basic() {
        let mut c = Cursor::new(b"hello\r\nworld\r\n".to_vec());
        let mut s = String::new();
        read_line(&mut c, &mut s).await.unwrap();
        assert_eq!(s, "hello");
        s.clear();
        read_line(&mut c, &mut s).await.unwrap();
        assert_eq!(s, "world");
    }

    #[tokio::test]
    async fn http_200_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.0 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });

        let mut cfg = Config {
            relay_method: crate::config::ProxyMethod::Http,
            dest_host: "example.com".into(),
            dest_port: 443,
            ..Config::default()
        };
        let mut s = TcpStream::connect(addr).await.unwrap();
        match begin(&mut s, &mut cfg).await.unwrap() {
            HttpStart::Ok => {}
            HttpStart::Retry => panic!("expected Ok"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_302_redirect_updates_relay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // The server only needs to send headers; we don't need the
            // request body, so read a small chunk to ensure the client
            // sent something, then respond.
            let mut buf = vec![0u8; 1024];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(
                b"HTTP/1.0 302 Found\r\nLocation: //newproxy.example.com:8080/path\r\n\r\n",
            )
            .await
            .unwrap();
        });

        let mut cfg = Config {
            relay_method: crate::config::ProxyMethod::Http,
            relay_host: Some("oldproxy.example.com".into()),
            relay_port: 3128,
            dest_host: "example.com".into(),
            dest_port: 443,
            ..Config::default()
        };
        let mut s = TcpStream::connect(addr).await.unwrap();
        match begin(&mut s, &mut cfg).await.unwrap() {
            HttpStart::Retry => {}
            HttpStart::Ok => panic!("expected Retry"),
        }
        assert_eq!(cfg.relay_host.as_deref(), Some("newproxy.example.com"));
        assert_eq!(cfg.relay_port, 8080);
        server.await.unwrap();
    }
}
