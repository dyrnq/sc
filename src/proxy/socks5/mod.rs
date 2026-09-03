//! SOCKS v5 handshake (Phases 2 + 4).
//!
//! Phase 2 implements the NOAUTH path and CONNECT request for IPv4, IPv6,
//! and DOMAINNAME ATYP. Phase 4 adds the USERPASS subnegotiation.
//!
//! Split into:
//!
//! - [`handshake`] — the greeting parser/writer and method-selection reply.
//! - [`auth`] — RFC 1929 USERPASS subnegotiation.
//! - [`request`] — CONNECT request writer and reply reader.
//!
//! [`begin`] is the orchestrator: it chains the three steps in order and
//! surfaces the typed errors.

pub mod auth;
pub mod handshake;
pub mod request;

use tokio::net::TcpStream;

use crate::config::{Config, ResolveMode};
use crate::error::{Error, Result};

pub use handshake::method;

/// Parse a `-A` / `SOCKS5_AUTH` style list: comma-separated keywords like
/// `none,userpass`. Unknown keywords are silently dropped (matches
/// `connect.c::socks5_auth_parse` at lines 2197-2217).
pub fn parse_auth_list(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for token in spec.split(',') {
        let t = token.trim().to_ascii_lowercase();
        match t.as_str() {
            "none" | "noauth" | "no-auth" => out.push(handshake::method::NOAUTH),
            "userpass" | "user-password" | "user/pasword" | "password" => {
                out.push(handshake::method::USERPASS)
            }
            _ => {}
        }
    }
    out
}

/// Run the full SOCKS5 handshake. By the time this returns, the `stream`
/// is connected to the destination through the proxy.
pub async fn begin(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    let mut methods = match cfg.socks5_auth.as_deref() {
        Some(spec) => parse_auth_list(spec),
        None => vec![handshake::method::NOAUTH, handshake::method::USERPASS],
    };
    if methods.is_empty() {
        methods.push(handshake::method::NOAUTH);
    }

    handshake::write_greeting(stream, &methods).await?;
    let chosen = handshake::read_method_reply(stream).await?;

    match chosen {
        handshake::method::NOAUTH => {}
        handshake::method::USERPASS => auth::do_userpass(stream, cfg).await?,
        m => return Err(Error::Socks5UnsupportedMethod(m)),
    }

    request::write_connect(stream, cfg).await?;
    request::read_connect_reply(stream).await?;
    Ok(())
}

/// Pre-resolve the destination if `socks_resolve == Local`, replacing
/// `cfg.dest_host` with a textual IP. Done before building the CONNECT
/// request so that ATYP can be chosen.
pub async fn maybe_resolve_destination(cfg: &mut Config) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth_list_defaults() {
        assert_eq!(parse_auth_list("none"), vec![handshake::method::NOAUTH]);
        assert_eq!(
            parse_auth_list("none,userpass"),
            vec![handshake::method::NOAUTH, handshake::method::USERPASS]
        );
        assert_eq!(parse_auth_list("userpass"), vec![handshake::method::USERPASS]);
        assert!(parse_auth_list("gssapi,chap,unknown").is_empty());
    }
}