//! SOCKS v5 handshake (Phases 2 + 4).
//!
//! Phase 2 implements the NOAUTH path and CONNECT request for IPv4, IPv6, and
//! DOMAINNAME ATYP. Phase 4 adds the USERPASS subnegotiation.
//!
//! Wire formats:
//!
//! ```text
//! Greeting:          VER=5 | NMETHODS | METHODS...
//! Method reply:      VER | METHOD      (METHOD=0xFF means none accepted)
//! USERPASS subneg:   VER=1 | ULEN | UNAME | PLEN | PASSWD
//! USERPASS reply:    VER | STATUS      (0 = success)
//! CONNECT request:   VER=5 | CMD=1 | RSV=0 | ATYP | DST.ADDR | DST.PORT(2 BE)
//! CONNECT reply:     VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
//! ```
//!
//! `ATYP`: 0x01 IPv4 (4 bytes), 0x03 DOMAINNAME (1-byte-len + name),
//! 0x04 IPv6 (16 bytes).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Config, ResolveMode};
use crate::error::{Error, Result};

/// SOCKS5 auth method bytes (RFC 1928).
pub mod method {
    pub const NOAUTH: u8 = 0x00;
    pub const USERPASS: u8 = 0x02;
}

/// SOCKS5 address types.
pub mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAINNAME: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

/// Parse a `-a` / `SOCKS5_AUTH` style list: comma-separated keywords like
/// `none,userpass`. Unknown keywords are silently dropped (matches
/// `connect.c::socks5_auth_parse` at lines 2197-2217).
pub fn parse_auth_list(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for token in spec.split(',') {
        let t = token.trim().to_ascii_lowercase();
        match t.as_str() {
            "none" | "noauth" | "no-auth" => out.push(method::NOAUTH),
            "userpass" | "user-password" | "user/pasword" | "password" => out.push(method::USERPASS),
            _ => {}
        }
    }
    out
}

/// Run the full SOCKS5 handshake. By the time this returns, the `stream`
/// is connected to the destination through the proxy.
///
/// Phase 2 supports NOAUTH only; if the server picks USERPASS this returns
/// `Error::Todo("SOCKS5 USERPASS (Phase 4)")`.
pub async fn begin(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    let mut methods = match cfg.socks5_auth.as_deref() {
        Some(spec) => parse_auth_list(spec),
        None => vec![method::NOAUTH, method::USERPASS],
    };
    if methods.is_empty() {
        methods.push(method::NOAUTH);
    }

    send_greeting(stream, &methods).await?;
    let chosen = recv_method_reply(stream).await?;

    match chosen {
        method::NOAUTH => {}
        method::USERPASS => {
            socks5_do_auth_userpass(stream, cfg).await?;
        }
        m => return Err(Error::Socks5UnsupportedMethod(m)),
    }

    send_connect(stream, cfg).await?;
    recv_connect_reply(stream).await?;
    Ok(())
}

/// SOCKS5 USERPASS subnegotiation (RFC 1929).
///
/// Wire format (request): `VER=1 | ULEN | UNAME | PLEN | PASSWD`.
/// Wire format (reply): `VER | STATUS` (STATUS=0 is success).
async fn socks5_do_auth_userpass(stream: &mut TcpStream, cfg: &Config) -> Result<()> {
    let user = cfg
        .relay_user
        .clone()
        .or_else(|| crate::auth::determine_relay_user(cfg.relay_method, cfg.socks_version).ok().flatten())
        .ok_or(Error::Auth("missing SOCKS5 user"))?;
    let pass = crate::auth::readpass(
        "SOCKS5 password: ",
        cfg.relay_method,
        cfg.socks_version,
    )?;

    let user_bytes = user.as_bytes();
    let pass_bytes = pass.as_bytes();
    if user_bytes.len() > 255 || pass_bytes.len() > 255 {
        return Err(Error::Config("SOCKS5 username/password too long".into()));
    }

    let mut req = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
    req.push(0x01); // subnegotiation VER
    req.push(user_bytes.len() as u8);
    req.extend_from_slice(user_bytes);
    req.push(pass_bytes.len() as u8);
    req.extend_from_slice(pass_bytes);
    stream.write_all(&req).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x01 || resp[1] != 0x00 {
        return Err(Error::Socks5AuthFailed);
    }
    Ok(())
}

async fn send_greeting(stream: &mut TcpStream, methods: &[u8]) -> Result<()> {
    let n = methods.len();
    if n > 255 {
        return Err(Error::Config("SOCKS5 too many auth methods".into()));
    }
    let mut buf = Vec::with_capacity(2 + n);
    buf.push(0x05); // VER
    buf.push(n as u8);
    buf.extend_from_slice(methods);
    stream.write_all(&buf).await?;
    Ok(())
}

async fn recv_method_reply(stream: &mut TcpStream) -> Result<u8> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        return Err(Error::Config(format!("SOCKS5 method reply VER={}", buf[0])));
    }
    if buf[1] == 0xFF {
        return Err(Error::Socks5NoAuth);
    }
    Ok(buf[1])
}

/// Pre-resolve the destination if `socks_resolve == Local`, replacing
/// `cfg.dest_host` with a textual IP. Done before building the CONNECT
/// request so that ATYP can be chosen.
async fn maybe_resolve_destination(cfg: &mut Config) -> Result<()> {
    if !matches!(cfg.socks_resolve, ResolveMode::Local) {
        return Ok(());
    }
    // Try numeric first (short-circuit DNS for IP literals).
    if cfg.dest_host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let addrs = crate::resolve::resolve_host(&cfg.dest_host, cfg.dest_port, cfg.family).await?;
    let first = addrs
        .first()
        .ok_or_else(|| Error::Dns(format!("no addresses for {}", cfg.dest_host)))?;
    cfg.dest_host = first.ip().to_string();
    Ok(())
}

async fn send_connect(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    maybe_resolve_destination(cfg).await?;

    let host = cfg.dest_host.clone();
    let port = cfg.dest_port;
    let mut req = Vec::with_capacity(32);
    req.push(0x05); // VER
    req.push(0x01); // CMD = CONNECT
    req.push(0x00); // RSV

    // Choose ATYP. Parse the host string to determine type.
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(atyp::IPV4);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(atyp::IPV6);
        req.extend_from_slice(&v6.octets());
    } else {
        // Domain name.
        if host.len() > 255 {
            return Err(Error::Config(format!(
                "SOCKS5 destination hostname too long: {host}"
            )));
        }
        req.push(atyp::DOMAINNAME);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }

    req.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&req).await?;
    Ok(())
}

async fn recv_connect_reply(stream: &mut TcpStream) -> Result<()> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(Error::Config(format!("SOCKS5 reply VER={}", hdr[0])));
    }
    if hdr[1] != 0x00 {
        return Err(Error::Socks5Reply(hdr[1]));
    }
    let tail_len = match hdr[3] {
        atyp::IPV4 => 4 + 2,
        atyp::DOMAINNAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            1 + len[0] as usize + 2
        }
        atyp::IPV6 => 16 + 2,
        a => return Err(Error::Socks5Atyp(a)),
    };
    let mut sink = vec![0u8; tail_len];
    stream.read_exact(&mut sink).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth_list_defaults() {
        assert_eq!(parse_auth_list("none"), vec![method::NOAUTH]);
        assert_eq!(
            parse_auth_list("none,userpass"),
            vec![method::NOAUTH, method::USERPASS]
        );
        assert_eq!(parse_auth_list("userpass"), vec![method::USERPASS]);
        assert!(parse_auth_list("gssapi,chap,unknown").is_empty());
    }

    #[tokio::test]
    async fn full_noauth_handshake() {
        // Spin up a fake SOCKS5 server.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Read greeting: [5, n, ...]
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0x05);
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&method::NOAUTH));
            // Reply: pick NOAUTH.
            s.write_all(&[0x05, method::NOAUTH]).await.unwrap();
            // Read CONNECT.
            let mut conn = [0u8; 4];
            s.read_exact(&mut conn).await.unwrap();
            assert_eq!(conn, [0x05, 0x01, 0x00, atyp::IPV4]);
            let mut dst = [0u8; 6]; // IPv4(4) + port(2)
            s.read_exact(&mut dst).await.unwrap();
            assert_eq!(&dst[..4], &[1, 2, 3, 4]);
            assert_eq!(u16::from_be_bytes([dst[4], dst[5]]), 22);
            // Reply success, bound to 0.0.0.0:0.
            s.write_all(&[0x05, 0x00, 0x00, atyp::IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let mut cfg = Config::default();
        cfg.relay_method = crate::config::ProxyMethod::Socks;
        cfg.dest_host = "1.2.3.4".into();
        cfg.dest_port = 22;
        cfg.socks_resolve = ResolveMode::Remote;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        begin(&mut stream, &mut cfg).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn domainname_atyp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[0x05, method::NOAUTH]).await.unwrap();
            let mut conn = [0u8; 4];
            s.read_exact(&mut conn).await.unwrap();
            assert_eq!(conn[3], atyp::DOMAINNAME);
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            let mut name = vec![0u8; len[0] as usize];
            s.read_exact(&mut name).await.unwrap();
            assert_eq!(name, b"example.com");
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            s.write_all(&[0x05, 0x00, 0x00, atyp::IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let mut cfg = Config::default();
        cfg.dest_host = "example.com".into();
        cfg.dest_port = 443;
        cfg.socks_resolve = ResolveMode::Remote;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        begin(&mut stream, &mut cfg).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn userpass_handshake() {
        // Pin env vars for this test. Rust 2024 marked these as unsafe.
        unsafe {
            std::env::set_var("SOCKS5_PASSWD", "secret");
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Greeting
            let mut hdr = [0u8; 2];
            s.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; hdr[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            // Pick USERPASS.
            s.write_all(&[0x05, method::USERPASS]).await.unwrap();
            // Read USERPASS subneg
            let mut ver = [0u8; 1];
            s.read_exact(&mut ver).await.unwrap();
            assert_eq!(ver[0], 0x01);
            let mut ulen = [0u8; 1];
            s.read_exact(&mut ulen).await.unwrap();
            let mut uname = vec![0u8; ulen[0] as usize];
            s.read_exact(&mut uname).await.unwrap();
            assert_eq!(uname, b"alice");
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut pwd = vec![0u8; plen[0] as usize];
            s.read_exact(&mut pwd).await.unwrap();
            assert_eq!(pwd, b"secret");
            // Reply success.
            s.write_all(&[0x01, 0x00]).await.unwrap();
            // Read CONNECT
            let mut conn = [0u8; 4];
            s.read_exact(&mut conn).await.unwrap();
            assert_eq!(conn, [0x05, 0x01, 0x00, atyp::IPV4]);
            let mut dst = [0u8; 6];
            s.read_exact(&mut dst).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, atyp::IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let mut cfg = Config::default();
        cfg.relay_method = crate::config::ProxyMethod::Socks;
        cfg.relay_user = Some("alice".into());
        cfg.dest_host = "1.2.3.4".into();
        cfg.dest_port = 22;
        cfg.socks_resolve = ResolveMode::Remote;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        begin(&mut stream, &mut cfg).await.unwrap();
        server.await.unwrap();
        unsafe {
            std::env::remove_var("SOCKS5_PASSWD");
        }
    }
}
