//! Bypass-proxy table (CIDR + domain entries).
//!
//! Initialised from environment variables (`SOCKS5_DIRECT` /
//! `HTTP_DIRECT` / `CONNECT_DIRECT`) and from `-D` (auto-add local
//! interface addresses).
//!
//! Entry formats (matches `connect.c::initialize_direct_addr`):
//! - `addr[/mask]`: `10.0.0.0/8`, `192.168.1.0/255.255.255.0`,
//!   `192.168.1.` (trailing dot → /24)
//! - `hostname` or `*.hostname` (exact or subdomain match)
//! - `!` prefix = negative (everything but this matches)
//!
//! `check_direct(host)` returns `true` if the host should bypass the
//! proxy.

use std::net::Ipv4Addr;
use std::sync::Mutex;

use crate::config::Config;
use crate::error::Result;

/// A single direct-table entry.
#[derive(Debug, Clone)]
enum Entry {
    Cidr { addr: u32, mask: u32 },
    Domain { name: String, suffix_only: bool },
    Negative(Box<Entry>),
}

impl Entry {
    /// Does this entry match `host` (and its resolved `ip`, if any)?
    /// `Negative` inverts its inner; recursive negation is fine because
    /// `parse_entry` only produces one level of wrapping.
    fn matches(&self, host: &str, ip: Option<Ipv4Addr>) -> bool {
        match self {
            Entry::Cidr { addr, mask } => ip
                .map(|i| (u32::from(i) & mask) == (addr & mask))
                .unwrap_or(false),
            Entry::Domain { name, suffix_only } => {
                let lower = host.to_ascii_lowercase();
                if *suffix_only {
                    lower.len() > name.len() && lower.ends_with(name)
                } else {
                    lower == *name
                }
            }
            Entry::Negative(inner) => !inner.matches(host, ip),
        }
    }
}

/// Global direct table. Mutex-protected because `-D` enumeration and
/// env-var parsing happen at startup, and `check_direct` may be called
/// from any proxy path. In our model only startup mutates it, but the
/// Mutex keeps things simple.
static TABLE: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// Parse a single entry. Returns `None` on format errors (matches C's
/// `add_direct_addr` returning -1).
fn parse_entry(spec: &str) -> Option<Entry> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    let (negative, body) = if let Some(rest) = spec.strip_prefix('!') {
        (true, rest)
    } else {
        (false, spec)
    };
    // Try CIDR / host-with-mask first.
    if let Some(entry) = parse_cidr(body) {
        return Some(if negative {
            Entry::Negative(Box::new(entry))
        } else {
            entry
        });
    }
    // Otherwise treat as a hostname.
    let suffix_only = body.starts_with('.');
    let name = body.trim_start_matches('.').to_ascii_lowercase();
    let entry = Entry::Domain { name, suffix_only };
    Some(if negative {
        Entry::Negative(Box::new(entry))
    } else {
        entry
    })
}

fn parse_cidr(spec: &str) -> Option<Entry> {
    // Format 1: `a.b.c.d[/mask]`
    let (addr_part, mask_part) = match spec.find('/') {
        Some(i) => (&spec[..i], Some(&spec[i + 1..])),
        None => (spec, None),
    };
    // Trailing dot → /24 (e.g. `192.168.1.`).
    let (addr, mask) = if addr_part.ends_with('.') {
        // Pad with zeros: e.g. "192.168.1." → "192.168.1.0"
        let parts: Vec<&str> = addr_part.trim_end_matches('.').split('.').collect();
        if parts.len() > 4 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            octets[i] = p.parse().ok()?;
        }
        let ip = Ipv4Addr::from(octets);
        let m: u32 = if parts.len() >= 4 {
            0xFFFFFFFFu32
        } else {
            0xFFFFFFFFu32 << (8 * (4 - parts.len() as u32))
        };
        (ip, m)
    } else if let Some(mask_str) = mask_part {
        let ip: Ipv4Addr = addr_part.parse().ok()?;
        let m: u32 = if mask_str.contains('.') {
            // Dotted-quad mask.
            let mip: Ipv4Addr = mask_str.parse().ok()?;
            u32::from(mip)
        } else {
            // Bit count.
            let n: u32 = mask_str.parse().ok()?;
            if n > 32 {
                return None;
            }
            if n == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - n) }
        };
        (ip, m)
    } else {
        let ip: Ipv4Addr = addr_part.parse().ok()?;
        (ip, 0xFFFFFFFFu32) // single-host
    };
    Some(Entry::Cidr {
        addr: u32::from(addr),
        mask,
    })
}

/// Initialise the bypass table from environment variables (read by the
/// caller) and the `-D` flag. Returns the number of entries added.
pub fn initialize(entries: &[String], auto_local: bool) -> Result<usize> {
    let mut table = TABLE.lock().unwrap();
    table.clear();
    let mut added = 0;
    for spec in entries {
        if let Some(e) = parse_entry(spec) {
            table.push(e);
            added += 1;
        }
    }
    if auto_local {
        added += add_local_interfaces(&mut table);
    }
    Ok(added)
}

/// Initialise the bypass table from `cfg`: reads the per-method env
/// var (`SOCKS5_DIRECT` / `SOCKS4_DIRECT` / `HTTP_DIRECT`) plus the
/// catch-all `CONNECT_DIRECT` env var, both routed through
/// `parameters::getparam` so `.connectrc` / `/etc/connectrc` are
/// honoured. Then layers on local interface auto-add when `-D` is set.
pub fn init_from_config(cfg: &Config) {
    use crate::config::ProxyMethod;
    let key = match cfg.relay_method {
        ProxyMethod::Socks if cfg.socks_version == 5 => "SOCKS5_DIRECT",
        ProxyMethod::Socks => "SOCKS4_DIRECT",
        ProxyMethod::Http => "HTTP_DIRECT",
        ProxyMethod::Telnet | ProxyMethod::Direct | ProxyMethod::Undecided => "",
    };
    let mut entries: Vec<String> = Vec::new();
    if !key.is_empty()
        && let Some(s) = crate::parameters::getparam(key)
    {
        entries.extend(s.split(',').map(str::to_string));
    }
    if let Some(s) = crate::parameters::getparam("CONNECT_DIRECT") {
        entries.extend(s.split(',').map(str::to_string));
    }
    let auto = cfg.f_auto_direct;
    match initialize(&entries, auto) {
        Ok(n) if n > 0 => tracing::debug!(entries = n, "direct table loaded"),
        Ok(_) => {}
        Err(e) => tracing::error!("direct table: {e}"),
    }
}

/// Add local network interface IPv4 addresses to the table.
///
/// Uses `nix::ifaddrs::getifaddrs()` for the libc call and walks the
/// returned `InterfaceAddress` iterator. Each entry's `address` /
/// `netmask` are `Option<SockaddrStorage>`; we downcast to
/// `SockaddrIn` via `as_sockaddr_in()`, which validates the address
/// family and length before the cast — much safer than the previous
/// raw `(sockaddr *) → (sockaddr_in *)` cast.
#[cfg(unix)]
fn add_local_interfaces(table: &mut Vec<Entry>) -> usize {
    let addrs = match nix::ifaddrs::getifaddrs() {
        Ok(it) => it,
        Err(_) => return 0,
    };
    let mut added = 0;
    for ifaddr in addrs {
        let (Some(addr_storage), Some(mask_storage)) = (ifaddr.address, ifaddr.netmask) else {
            continue;
        };
        let (Some(sin_addr), Some(sin_mask)) =
            (addr_storage.as_sockaddr_in(), mask_storage.as_sockaddr_in())
        else {
            continue;
        };
        let addr = sin_addr.ip();
        let mask_ip = sin_mask.ip();
        table.push(Entry::Cidr {
            addr: u32::from(addr),
            mask: u32::from(mask_ip),
        });
        tracing::debug!(
            iface = %ifaddr.interface_name,
            addr = %addr,
            "adding local interface to direct table",
        );
        added += 1;
    }
    added
}

/// Windows stub: would call GetIpAddrTable from windows-sys IpHelper.
#[cfg(windows)]
fn add_local_interfaces(_table: &mut Vec<Entry>) -> usize {
    // TODO: implement via windows-sys Win32_NetworkManagement_IpHelper.
    0
}

#[cfg(not(any(unix, windows)))]
fn add_local_interfaces(_table: &mut Vec<Entry>) -> usize {
    0
}

/// Decide whether `host` should bypass the proxy. Domain entries match
/// `connect.c`'s `check_host` (case-insensitive exact or subdomain match);
/// `!`-prefixed entries negate their inner match.
pub fn check_direct(host: &str) -> bool {
    let table = TABLE.lock().unwrap();
    let ip = host.parse::<Ipv4Addr>().ok();
    table.iter().any(|e| e.matches(host, ip))
}

// ---- sockaddr helpers ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ProxyMethod};

    /// Serialises the tests that call `initialize(...)` (which clears the
    /// global `TABLE`) so they cannot interleave. Without this guard,
    /// one test's `check_direct` assertion can observe another test's
    /// table state when cargo runs them in parallel.
    static TABLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn parse_cidr_basic() {
        match parse_entry("10.0.0.0/8").unwrap() {
            Entry::Cidr { addr, mask } => {
                assert_eq!(u32::from(Ipv4Addr::new(10, 0, 0, 0)), addr);
                assert_eq!(0xFF000000, mask);
            }
            _ => panic!("expected Cidr"),
        }
    }

    #[test]
    fn parse_cidr_trailing_dot_implies_24() {
        match parse_entry("192.168.1.").unwrap() {
            Entry::Cidr { addr, mask } => {
                assert_eq!(u32::from(Ipv4Addr::new(192, 168, 1, 0)), addr);
                assert_eq!(0xFFFFFF00, mask);
            }
            _ => panic!("expected Cidr"),
        }
    }

    #[test]
    fn parse_hostname_with_negative() {
        match parse_entry("!example.com").unwrap() {
            Entry::Negative(inner) => match *inner {
                Entry::Domain { ref name, .. } => assert_eq!(name, "example.com"),
                _ => panic!("expected Domain inside Negative"),
            },
            _ => panic!("expected Negative"),
        }
    }

    #[test]
    fn initialize_then_check_direct() {
        let _g = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        initialize(&["10.0.0.0/8".into(), "192.168.1.0/24".into()], false).unwrap();
        assert!(check_direct("10.0.0.1"));
        assert!(check_direct("192.168.1.42"));
        assert!(!check_direct("8.8.8.8"));
    }

    /// Domain matching: exact (case-insensitive) and suffix-only (`*.host`).
    /// `suffix_only` requires the host to be strictly longer than the
    /// suffix so that `*.example.com` doesn't match `example.com` itself.
    #[test]
    fn check_direct_domain_match() {
        let _g = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        initialize(&["example.com".into(), ".internal.corp".into()], false).unwrap();
        assert!(check_direct("example.com"));
        assert!(check_direct("EXAMPLE.COM"));
        assert!(!check_direct("example.org"));

        assert!(check_direct("svc.internal.corp"));
        assert!(!check_direct("internal.corp")); // suffix-only, not equal
        assert!(!check_direct("corp"));
    }

    /// Negative domain: matches everything *except* the listed host.
    /// Mirrors `connect.c::check_host` returning true when the host
    /// is NOT in the table.
    #[test]
    fn check_direct_negative_domain() {
        let _g = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        initialize(&["!blocked.example".into()], false).unwrap();
        assert!(check_direct("allowed.example"));
        assert!(check_direct("anything.else"));
        assert!(!check_direct("blocked.example"));
    }

    /// `init_from_config` reads `SOCKS5_DIRECT` from the connectrc
    /// table (via `parameters::getparam`) when env is unset. The
    /// resulting CIDR entries are visible through `check_direct`.
    /// Uses a key unique to this test so it doesn't race the parallel
    /// `parameters::tests` that also poke `socks5_direct`.
    #[test]
    fn init_from_config_loads_socks5_direct_from_connectrc() {
        let _g = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: test owns SOCKS5_DIRECT during its run.
        unsafe {
            std::env::remove_var("SOCKS5_DIRECT");
        }
        // Pre-populate connectrc-style entry via TABLE.
        let prev = crate::parameters::_insert_for_test("SOCKS5_DIRECT", "172.16.0.0/12");

        let cfg = Config {
            relay_method: ProxyMethod::Socks,
            socks_version: 5,
            ..Config::default()
        };
        init_from_config(&cfg);

        assert!(check_direct("172.16.5.5"));
        assert!(!check_direct("8.8.8.8"));

        // Restore prior TABLE entry.
        let mut t = crate::parameters::TABLE.lock().unwrap();
        match prev {
            Some(v) => {
                t.insert("SOCKS5_DIRECT".into(), v);
            }
            None => {
                t.remove("SOCKS5_DIRECT");
            }
        }
    }

    /// `CONNECT_DIRECT` is the per-method-catch-all: it should be
    /// picked up regardless of which proxy method is configured. Pins
    /// that the connectrc path applies uniformly across methods.
    #[test]
    fn init_from_config_connect_direct_applies_to_any_method() {
        let _g = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: test owns these env vars during its run.
        unsafe {
            std::env::remove_var("CONNECT_DIRECT");
            std::env::remove_var("HTTP_DIRECT");
            std::env::remove_var("SOCKS5_DIRECT");
        }
        let prev = crate::parameters::_insert_for_test("CONNECT_DIRECT", "100.0.0.0/8");

        let cfg = Config {
            relay_method: ProxyMethod::Http,
            ..Config::default()
        };
        init_from_config(&cfg);

        assert!(check_direct("100.5.6.7"));
        assert!(!check_direct("8.8.8.8"));

        // Restore prior TABLE entry.
        let mut t = crate::parameters::TABLE.lock().unwrap();
        match prev {
            Some(v) => {
                t.insert("CONNECT_DIRECT".into(), v);
            }
            None => {
                t.remove("CONNECT_DIRECT");
            }
        }
    }
}
