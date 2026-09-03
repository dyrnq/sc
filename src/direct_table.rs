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

use crate::error::Result;

/// A single direct-table entry.
#[derive(Debug, Clone)]
enum Entry {
    Cidr { addr: u32, mask: u32 },
    Domain { name: String, suffix_only: bool },
    Negative(Box<Entry>),
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

/// Add local network interface IPv4 addresses to the table.
#[cfg(unix)]
fn add_local_interfaces(table: &mut Vec<Entry>) -> usize {
    use std::ffi::CStr;

    unsafe extern "C" {
        fn getifaddrs(ifap: *mut *mut libc::ifaddrs) -> libc::c_int;
        fn freeifaddrs(ifa: *mut libc::ifaddrs);
    }

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a NULL or valid pointer to *ifap.
    let r = unsafe { getifaddrs(&mut ifap) };
    if r != 0 || ifap.is_null() {
        return 0;
    }
    let mut added = 0;
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: cur is a valid pointer from getifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr is a valid sockaddr from the kernel.
            let sa_family = unsafe { (*ifa.ifa_addr).sa_family };
            if sa_family == libc::AF_INET as libc::sa_family_t && !ifa.ifa_netmask.is_null() {
                let addr = unsafe {
                    &*((ifa.ifa_addr as *const libc::sockaddr) as *const libc::sockaddr_in)
                };
                let mask = unsafe {
                    &*((ifa.ifa_netmask as *const libc::sockaddr) as *const libc::sockaddr_in)
                };
                table.push(Entry::Cidr {
                    addr: u32::from_be(addr.sin_addr.s_addr),
                    mask: u32::from_be(mask.sin_addr.s_addr),
                });
                if !ifa.ifa_name.is_null() {
                    // SAFETY: ifa_name is a valid C string.
                    let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
                    eprintln!(
                        "DEBUG: -D adding local iface {} addr={:?}",
                        name.to_string_lossy(),
                        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                    );
                }
                added += 1;
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: ifap was returned by getifaddrs.
    unsafe { freeifaddrs(ifap) };
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

/// Decide whether `host` should bypass the proxy.
///
/// For now this returns false unless a CIDR matches a numeric IP. Hostname
/// matching against the table is deferred to Phase 12 polish.
pub fn check_direct(host: &str) -> bool {
    let table = TABLE.lock().unwrap();
    let ip = host.parse::<Ipv4Addr>().ok();
    for entry in table.iter() {
        match entry {
            Entry::Cidr { addr, mask } => {
                if let Some(ip) = ip {
                    let v = u32::from(ip);
                    if (v & mask) == (addr & mask) {
                        return true;
                    }
                }
            }
            Entry::Domain { name, suffix_only } => {
                let lower = host.to_ascii_lowercase();
                if *suffix_only {
                    if lower.ends_with(name) && lower.len() > name.len() {
                        return true;
                    }
                } else if lower == *name {
                    return true;
                }
            }
            Entry::Negative(inner) => {
                if !matches!(inner.as_ref(), Entry::Cidr { .. } | Entry::Domain { .. }) {
                    continue;
                }
                let inner_match = match inner.as_ref() {
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
                    _ => false,
                };
                if !inner_match {
                    return true;
                }
            }
        }
    }
    false
}

// ---- sockaddr helpers ----

#[cfg(test)]
mod tests {
    use super::*;

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
        initialize(&["10.0.0.0/8".into(), "192.168.1.0/24".into()], false).unwrap();
        assert!(check_direct("10.0.0.1"));
        assert!(check_direct("192.168.1.42"));
        assert!(!check_direct("8.8.8.8"));
    }
}
