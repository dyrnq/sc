//! Override the resolver's nameserver list (Linux only).
//!
//! Mirrors `connect.c::switch_ns` (lines 1809-1818): when `-R <IPv4>` is
//! given, replace `nscount = 1` and `nsaddr_list[0]` in the glibc resolver
//! state with that IP. Other platforms are a no-op.
//!
//! Implementation note: glibc exports `_res` as a versioned symbol
//! (`_res@GLIBC_2.2.5`) and `rust-lld` does not resolve versioned
//! references. We work around this by linking a tiny C shim
//! (`csrc/switch_ns_shim.c`) which references `_res` through the
//! standard GNU linker path and exposes a Rust-friendly extern "C"
//! function.

#[cfg(target_os = "linux")]
use crate::error::Error;
use crate::error::Result;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn sc_res_init() -> i32;
    fn sc_switch_ns_set(s_addr: u32);
}

#[cfg(target_os = "linux")]
pub fn apply(ip: std::net::Ipv4Addr) -> Result<()> {
    unsafe {
        let r = sc_res_init();
        if r != 0 {
            return Err(Error::Config(format!("res_init failed: {r}")));
        }
        sc_switch_ns_set(u32::from(ip).to_be());
    }
    eprintln!("DEBUG: switch_ns using nameserver {ip}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply(_ip: std::net::Ipv4Addr) -> Result<()> {
    // No glibc resolver state to override on non-Linux platforms.
    Ok(())
}
