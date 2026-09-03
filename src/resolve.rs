//! DNS resolution via hickory-resolver.
//!
//! Single global `TokioResolver`, initialised once at startup via
//! `init()`. All `resolve_host()` calls reuse it. hickory implements
//! the DNS protocol itself (UDP/TCP + TTL cache); libc `getaddrinfo`
//! is not involved.
//!
//! Two knobs at startup:
//! - `-R <IPv4>` (via `cfg.socks_ns`): use that IP as the only upstream
//!   nameserver. Does NOT read `/etc/resolv.conf`.
//! - Otherwise: `ResolverConfig::default()` reads `/etc/resolv.conf` on
//!   Unix, registry on Windows.
//!
//! hickory auto-loads `/etc/hosts` (via `Hosts::from_system()`) — we do
//! not parse it manually.
//!
//! On Windows the system hosts file is loaded from
//! `%SystemRoot%\System32\drivers\etc\hosts` automatically.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::OnceLock;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use crate::config::Family;
use crate::error::{Error, Result};

static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

/// Initialise the global resolver. Call exactly once at startup, before
/// any `resolve_host()` call.
pub fn init(override_ns: Option<Ipv4Addr>) -> Result<()> {
    let config = match override_ns {
        Some(ip) => {
            // -R <IPv4>: build a config with that IP as the only upstream.
            ResolverConfig::from_parts(
                None,
                Vec::new(),
                vec![NameServerConfig::new(
                    IpAddr::V4(ip),
                    /* trust_negative_responses = */ true,
                    vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
                )],
            )
        }
        None => ResolverConfig::default(),
    };

    let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| Error::Config(format!("resolver init failed: {e}")))?;

    RESOLVER
        .set(resolver)
        .map_err(|_| Error::Config("resolve::init called more than once".into()))?;
    if let Some(ns) = override_ns {
        tracing::debug!("resolver using nameserver {ns}");
    } else {
        tracing::debug!("resolver using system DNS config");
    }
    Ok(())
}

/// Resolve `host:port` into one or more `SocketAddr`s, filtered by `family`.
///
/// Returns up to one IPv4 and one IPv6 candidate.
pub async fn resolve_host(host: &str, port: u16, family: Family) -> Result<Vec<SocketAddr>> {
    // 1. Numeric short-circuit — IP literals bypass the resolver.
    if let Ok(v4) = host.parse::<Ipv4Addr>()
        && matches!(family, Family::V4 | Family::Any)
    {
        return Ok(vec![SocketAddr::V4(SocketAddrV4::new(v4, port))]);
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>()
        && matches!(family, Family::V6 | Family::Any)
    {
        return Ok(vec![SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0))]);
    }

    // 2. DNS lookup via hickory.
    let resolver = RESOLVER
        .get()
        .ok_or_else(|| Error::Config("resolve::init not called".into()))?;

    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| Error::Dns(format!("{host}: {e}")))?;

    let mut out: Vec<SocketAddr> = Vec::with_capacity(2);
    for addr in lookup.iter() {
        let keep = matches!(
            (family, addr),
            (Family::Any, _) | (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_))
        );
        if keep && !out.iter().any(|a| same_ip(*a, addr)) {
            out.push(SocketAddr::new(addr, port));
            // Cap at one of each family — same policy as before.
            match family {
                Family::Any if out.len() >= 2 => break,
                Family::V4 | Family::V6 if !out.is_empty() => break,
                _ => {}
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

fn same_ip(a: SocketAddr, b: IpAddr) -> bool {
    a.ip() == b
}

#[cfg(test)]
mod tests {
    use super::*;

    // resolve_host() requires init() to have been called and is async;
    // exercising the lookup path needs a live resolver (integration test
    // territory). The numeric short-circuit branches are covered
    // indirectly by `tests/socks5.rs`, which uses IP literals.

    #[test]
    fn same_ip_matches_v4() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(same_ip(a, b));
    }

    #[test]
    fn same_ip_rejects_different() {
        let a: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(!same_ip(a, b));
    }
}
