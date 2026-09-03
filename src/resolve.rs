//! DNS resolution that filters by address family.
//!
//! `connect.c` is IPv4-only and uses `gethostbyname`. `sc` uses Tokio's async
//! `lookup_host` and filters results by `--family {v4|v6|any}` (default `any`).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::net::lookup_host;

use crate::config::Family;
use crate::error::{Error, Result};

/// Resolve `host:port` into one or more `SocketAddr`s, filtered by `family`.
///
/// Returns up to one IPv4 and one IPv6 candidate (one of each), preferring
/// the first of each family returned by the resolver.
pub async fn resolve_host(host: &str, port: u16, family: Family) -> Result<Vec<SocketAddr>> {
    // 1. Try numeric literal first to short-circuit DNS for things like `1.2.3.4`
    //    or `[::1]:80` style usage. Note: `host` here is the bare hostname — the
    //    caller passes port separately, so we synthesise `(host, port)`.
    let mut out: Vec<SocketAddr> = Vec::with_capacity(2);

    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        if matches!(family, Family::V4 | Family::Any) {
            out.push(SocketAddr::V4(SocketAddrV4::new(v4, port)));
        }
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        if matches!(family, Family::V6 | Family::Any) {
            out.push(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)));
        }
    } else {
        // 2. Async DNS lookup.
        let iter = lookup_host((host, port))
            .await
            .map_err(|e| Error::Dns(format!("{host}: {e}")))?;
        for addr in iter {
            let keep = match (family, addr) {
                (Family::Any, _) => true,
                (Family::V4, SocketAddr::V4(_)) => true,
                (Family::V6, SocketAddr::V6(_)) => true,
                _ => false,
            };
            if keep && !out.iter().any(|a| same_addr(*a, addr)) {
                out.push(addr);
                // Cap at one of each family — more is wasteful.
                match family {
                    Family::Any if out.len() >= 2 => break,
                    Family::V4 | Family::V6 if out.len() >= 1 => break,
                    _ => {}
                }
            }
        }
    }

    if out.is_empty() {
        return Err(Error::Dns(format!(
            "no {} addresses for {host}",
            match family {
                Family::V4 => "IPv4",
                Family::V6 => "IPv6",
                Family::Any => "usable",
            }
        )));
    }
    Ok(out)
}

fn same_addr(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(x), SocketAddr::V4(y)) => x == y,
        (SocketAddr::V6(x), SocketAddr::V6(y)) => x == y,
        _ => false,
    }
}
