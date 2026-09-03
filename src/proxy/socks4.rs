//! SOCKS v4 / v4a handshake (Phase 7).
//!
//! Wire formats:
//!
//! ```text
//! Connect request (v4):  VN=4 | CD=1 | PORT(2 BE) | ADDR(4) | USERID\0
//! Connect request (v4a): VN=4 | CD=1 | PORT(2 BE) | ADDR=0.0.0.X | USERID\0 | HOSTNAME\0
//! Connect reply:         VN(0) | CD | DSTPORT(2) | DSTIP(4)     (8 bytes)
//! ```
//!
//! SOCKS4a is signalled by setting the last IP byte to non-zero when the
//! destination couldn't be pre-resolved (i.e. `socks_resolve == Remote`).
//! The proxy uses the appended `HOSTNAME` to perform DNS itself.
//!
//! Mirrors `connect.c::begin_socks4_relay` (lines 2358-2403).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Config, ResolveMode};
use crate::error::{Error, Result};

/// SOCKS4 reply codes.
pub mod reply {
    pub const SUCCEEDED: u8 = 0x5A; // 90
    pub const REJECTED: u8 = 0x5B;
    pub const IDENT_FAILED: u8 = 0x5D;
}

/// SOCKS4a marker: last octet of the ADDR field is set to non-zero to
/// signal that the trailing `HOSTNAME\0` should be used for resolution.
const SOCKS4A_MARKER: u8 = 0x01;

/// Run the SOCKS4 / 4a handshake. By the time this returns, the `stream`
/// is connected to the destination through the proxy.
#[tracing::instrument(skip(stream), fields(version = cfg.socks_version))]
pub async fn begin(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    let user = cfg
        .relay_user
        .clone()
        .or_else(|| crate::auth::determine_relay_user(cfg.relay_method, cfg.socks_version).ok().flatten())
        .ok_or_else(|| Error::Auth("missing SOCKS4 user".into()))?;

    // Resolve dest_host if needed (socks_resolve == Local).
    let dest_ip = maybe_resolve_destination(cfg).await?;

    // Build the request.
    let user_bytes = user.as_bytes();
    let dest_host_bytes = cfg.dest_host.as_bytes();
    if user_bytes.len() > 255 {
        return Err(Error::Config("SOCKS4 username too long".into()));
    }
    if dest_host_bytes.len() > 255 {
        return Err(Error::Config("SOCKS4 hostname too long".into()));
    }

    let mut req = Vec::with_capacity(9 + user_bytes.len() + 1 + dest_host_bytes.len() + 1);
    req.push(0x04); // VN
    req.push(0x01); // CD = CONNECT
    req.extend_from_slice(&cfg.dest_port.to_be_bytes());

    let use_socks4a = matches!(cfg.socks_resolve, ResolveMode::Remote) && dest_ip.is_none();
    if let Some(ip) = dest_ip {
        req.extend_from_slice(&ip.octets());
    } else {
        // SOCKS4a marker: 0.0.0.X where X != 0.
        req.extend_from_slice(&[0, 0, 0, SOCKS4A_MARKER]);
    }
    req.extend_from_slice(user_bytes);
    req.push(0); // USERID null terminator

    if use_socks4a {
        // SOCKS4a extension: trailing HOSTNAME\0 after USERID\0.
        req.extend_from_slice(dest_host_bytes);
        req.push(0); // HOSTNAME null terminator
    }

    stream.write_all(&req).await?;

    // Read 8-byte reply: VN(1) | CD(1) | DSTPORT(2) | DSTIP(4).
    let mut resp = [0u8; 8];
    stream.read_exact(&mut resp).await?;
    if resp[1] != reply::SUCCEEDED {
        return Err(Error::Socks4Reply(resp[1]));
    }
    Ok(())
}

/// Pre-resolve `dest_host` if `socks_resolve == Local`. Returns:
/// - `Some(Ipv4Addr)` if resolved
/// - `None` if REMOTE (caller will emit SOCKS4a marker)
async fn maybe_resolve_destination(cfg: &mut Config) -> Result<Option<std::net::Ipv4Addr>> {
    if !matches!(cfg.socks_resolve, ResolveMode::Local) {
        return Ok(None);
    }
    // If the host is already an IPv4 literal, short-circuit.
    if let Ok(ip) = cfg.dest_host.parse::<std::net::Ipv4Addr>() {
        return Ok(Some(ip));
    }
    // For SOCKS4 the wire format only carries IPv4. Try lookup_host and
    // pick the first IPv4 address.
    let addrs = crate::resolve::resolve_host(&cfg.dest_host, cfg.dest_port, cfg.family).await?;
    for addr in addrs {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            // Replace dest_host so subsequent code paths (none in SOCKS4,
            // but the relay in main.rs) see an IP literal.
            cfg.dest_host = v4.to_string();
            return Ok(Some(v4));
        }
    }
    Err(Error::Dns(format!(
        "no IPv4 address for {} (SOCKS4 needs IPv4)",
        cfg.dest_host
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks4_ipv4_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Read request: VN=4, CD=1, PORT=2, IP=4, USERID\0
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 4);
            assert_eq!(req[1], 1);
            assert_eq!(u16::from_be_bytes([req[2], req[3]]), 22);
            assert_eq!(&req[4..8], &[1, 2, 3, 4]);
            assert_eq!(req[8], b'a');
            assert_eq!(req[9], 0);
            // Reply: 0x00, SUCCEEDED, port(2), ip(4)
            s.write_all(&[0x00, reply::SUCCEEDED, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let mut cfg = Config::default();
        cfg.relay_method = crate::config::ProxyMethod::Socks;
        cfg.socks_version = 4;
        cfg.relay_user = Some("a".into());
        cfg.dest_host = "1.2.3.4".into();
        cfg.dest_port = 22;
        cfg.socks_resolve = ResolveMode::Local;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        begin(&mut stream, &mut cfg).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks4a_handshake_appends_hostname() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 8];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 4);
            assert_eq!(hdr[1], 1);
            assert_eq!(u16::from_be_bytes([hdr[2], hdr[3]]), 443);
            // ADDR field — should be 0.0.0.1 (SOCKS4a marker).
            assert_eq!(&hdr[4..8], &[0, 0, 0, 1]);

            // Read USERID\0
            let mut user = [0u8; 6];
            s.read_exact(&mut user).await.unwrap();
            assert_eq!(&user, b"alice\0");
            // Read HOSTNAME\0
            let mut host = [0u8; 12];
            s.read_exact(&mut host).await.unwrap();
            assert_eq!(&host, b"example.com\0");

            s.write_all(&[0x00, reply::SUCCEEDED, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let mut cfg = Config::default();
        cfg.relay_method = crate::config::ProxyMethod::Socks;
        cfg.socks_version = 4;
        cfg.relay_user = Some("alice".into());
        cfg.dest_host = "example.com".into();
        cfg.dest_port = 443;
        cfg.socks_resolve = ResolveMode::Remote;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        begin(&mut stream, &mut cfg).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks4_reply_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut sink = [0u8; 64];
            let _ = s.read(&mut sink).await;
            s.write_all(&[0x00, reply::REJECTED, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let mut cfg = Config::default();
        cfg.relay_method = crate::config::ProxyMethod::Socks;
        cfg.socks_version = 4;
        cfg.relay_user = Some("u".into());
        cfg.dest_host = "1.2.3.4".into();
        cfg.dest_port = 22;
        cfg.socks_resolve = ResolveMode::Local;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let err = begin(&mut stream, &mut cfg).await.unwrap_err();
        match err {
            Error::Socks4Reply(c) => assert_eq!(c, reply::REJECTED),
            _ => panic!("expected Socks4Reply"),
        }
        server.await.unwrap();
    }
}