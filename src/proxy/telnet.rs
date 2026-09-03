//! TELNET proxy handshake (Phase 8).
//!
//! Mirrors `connect.c::begin_telnet_relay` (lines 2612-2670):
//!
//! 1. Expand `-c` template (`%h` → host, `%p` → port; `\r`/`\n`/`\t` →
//!    CR/LF/TAB escapes), send followed by `\r\n`.
//! 2. Read response lines until:
//!    - a line contains "connected to" → handshake succeeds
//!    - a line contains any of " failed", " refused", " rejected",
//!      " closed" → handshake fails
//! 3. EOF before either match → error.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::{Error, Result};

const GOOD_PHRASE: &str = "connected to";
const BAD_PHRASES: &[&str] = &[" failed", " refused", " rejected", " closed"];

/// Expand `%h`/`%p` and `\\r` / `\\n` / `\\t` in `fmt`. Mirrors
/// `connect.c::expand_host_and_port` (lines 564-616).
pub fn expand(fmt: &str, host: &str, port: u16) -> String {
    let mut out = String::with_capacity(fmt.len() + 16);
    let bytes = fmt.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'%' if i + 1 < bytes.len() => match bytes[i + 1] {
                b'h' => {
                    out.push_str(host);
                    i += 2;
                }
                b'p' => {
                    out.push_str(&port.to_string());
                    i += 2;
                }
                _ => {
                    // Unknown %-escape: drop the '%' (matches C).
                    i += 1;
                }
            },
            b'\\' if i + 1 < bytes.len() => match bytes[i + 1] {
                b'r' => {
                    out.push('\r');
                    i += 2;
                }
                b'n' => {
                    out.push('\n');
                    i += 2;
                }
                b't' => {
                    out.push('\t');
                    i += 2;
                }
                _ => {
                    // Unknown backslash escape: drop the '\\', keep the
                    // following character (matches C lines 604-606). So
                    // `\\x` in source becomes `\x` in output.
                    i += 1;
                }
            },
            _ => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// Run the TELNET proxy handshake. By the time this returns, the
/// `stream` is connected to the destination through the proxy.
#[tracing::instrument(skip(stream), fields(?cfg.telnet_command))]
pub async fn begin(stream: &mut TcpStream, cfg: &Config) -> Result<()> {
    let template = cfg
        .telnet_command
        .as_deref()
        .ok_or_else(|| Error::Config("missing -c telnet command template".into()))?;

    let cmd = expand(template, &cfg.dest_host, cfg.dest_port);
    let mut req = cmd;
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    // Read response lines until good or bad phrase is detected.
    let mut line = String::new();
    loop {
        line.clear();
        if read_line(stream, &mut line).await? {
            // EOF.
            return Err(Error::Telnet("EOF reading proxy response".into()));
        }
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains(GOOD_PHRASE) {
            return Ok(());
        }
        for bad in BAD_PHRASES {
            if lower.contains(bad) {
                return Err(Error::Telnet(format!("bad phrase: {bad}")));
            }
        }
        // No match: keep reading.
    }
}

/// Read one CRLF-terminated line into `buf`. Returns `Ok(true)` on EOF,
/// `Ok(false)` on a normal line read.
async fn read_line<R: AsyncRead + Unpin>(r: &mut R, buf: &mut String) -> Result<bool> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            // EOF.
            return Ok(true);
        }
        if byte[0] == b'\n' {
            return Ok(false);
        }
        if byte[0] != b'\r' {
            buf.push(byte[0] as char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_basic() {
        assert_eq!(
            expand("telnet %h %p", "example.com", 22),
            "telnet example.com 22"
        );
    }

    #[test]
    fn expand_backslash_escapes() {
        // \n and \t produce CR-equivalents. A backslash followed by
        // anything else (like another backslash) drops the backslash and
        // passes the rest through (matches C lines 604-606).
        assert_eq!(expand("a\\nb\\tc\\\\d", "h", 1), "a\nb\tcd");
    }

    #[test]
    fn expand_unknown_escape_drops_marker() {
        // Unknown %-escape: drop the '%' (matches C lines 585-587).
        assert_eq!(expand("foo%xbar", "h", 1), "fooxbar");
    }

    #[tokio::test]
    async fn telnet_connected_to() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let _ = s.read(&mut buf).await.unwrap();
            // Send banner lines and a "connected to" line.
            s.write_all(b"Trying...\r\nConnected to example.com.\r\n")
                .await
                .unwrap();
        });

        let cfg = Config {
            relay_method: crate::config::ProxyMethod::Telnet,
            telnet_command: Some("telnet %h %p".into()),
            dest_host: "example.com".into(),
            dest_port: 22,
            ..Config::default()
        };

        let mut s = TcpStream::connect(addr).await.unwrap();
        begin(&mut s, &cfg).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn telnet_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 64];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"connect: connection refused\r\n")
                .await
                .unwrap();
        });

        let cfg = Config {
            relay_method: crate::config::ProxyMethod::Telnet,
            telnet_command: Some("open %h %p".into()),
            dest_host: "host".into(),
            dest_port: 22,
            ..Config::default()
        };

        let mut s = TcpStream::connect(addr).await.unwrap();
        let err = begin(&mut s, &cfg).await.unwrap_err();
        match err {
            Error::Telnet(msg) => assert!(msg.contains("refused")),
            _ => panic!("expected Telnet error"),
        }
        server.await.unwrap();
    }
}
