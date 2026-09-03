//! Global configuration and parsed state.
//!
//! All runtime options live here. The struct is built once by `cli::parse`
//! and then read by the rest of the program.

use std::net::Ipv4Addr;
use std::str::FromStr;

/// Address-family selection. `--family v4|v6|any`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Family {
    #[default]
    Any,
    V4,
    V6,
}

impl FromStr for Family {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Ok(Family::Any),
            "v4" | "ipv4" | "4" => Ok(Family::V4),
            "v6" | "ipv6" | "6" => Ok(Family::V6),
            _ => Err(()),
        }
    }
}

/// The proxy method selected for this invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMethod {
    Undecided,
    Direct,
    Socks,
    Http,
    Telnet,
}

impl ProxyMethod {
    pub fn name(self) -> &'static str {
        match self {
            ProxyMethod::Undecided => "UNDECIDED",
            ProxyMethod::Direct => "DIRECT",
            ProxyMethod::Socks => "SOCKS",
            ProxyMethod::Http => "HTTP",
            ProxyMethod::Telnet => "TELNET",
        }
    }
}

/// DNS resolution mode for the SOCKS path. `Both` is parsed but treated as
/// `Remote` (mirrors `connect.c` behaviour where `RESOLVE_BOTH` is not branched).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResolveMode {
    #[default]
    Unknown,
    Local,
    Remote,
    Both,
}

impl FromStr for ResolveMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "local" => Ok(ResolveMode::Local),
            "remote" => Ok(ResolveMode::Remote),
            "both" => Ok(ResolveMode::Both),
            _ => Err(()),
        }
    }
}

impl ResolveMode {
    pub fn name(self) -> &'static str {
        match self {
            ResolveMode::Unknown => "UNKNOWN",
            ResolveMode::Local => "LOCAL",
            ResolveMode::Remote => "REMOTE",
            ResolveMode::Both => "BOTH",
        }
    }
}

/// Where the local side of the relay comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalType {
    /// stdin / stdout (the default).
    Stdio,
    /// Listen on the given TCP port and accept one connection per cycle.
    Socket(u16),
}

impl LocalType {
    pub fn name(self) -> &'static str {
        match self {
            LocalType::Stdio => "stdio",
            LocalType::Socket(_) => "socket",
        }
    }
}

/// Proxy authentication state — for HTTP CONNECT retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyAuthType {
    #[default]
    None,
    Basic,
}

/// Parsed configuration. Built by `cli::parse`.
#[derive(Debug, Clone)]
pub struct Config {
    pub relay_method: ProxyMethod,
    pub relay_host: Option<String>,
    pub relay_port: u16,
    pub relay_user: Option<String>,

    pub socks_version: u8, // 4 or 5
    pub socks_resolve: ResolveMode,
    pub socks_ns: Option<Ipv4Addr>,
    pub socks5_auth: Option<String>,

    pub dest_host: String,
    pub dest_port: u16,

    pub local_type: LocalType,
    pub f_hold_session: bool,

    pub f_auto_direct: bool,
    pub connect_timeout: u32,
    pub read_timeout_ms: u64,
    pub f_debug: u8,

    pub family: Family,
    pub telnet_command: Option<String>,
    pub proxy_auth: ProxyAuthType,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            relay_method: ProxyMethod::Undecided,
            relay_host: None,
            relay_port: 0,
            relay_user: None,
            socks_version: 5,
            socks_resolve: ResolveMode::Unknown,
            socks_ns: None,
            socks5_auth: None,
            dest_host: String::new(),
            dest_port: 0,
            local_type: LocalType::Stdio,
            f_hold_session: false,
            f_auto_direct: false,
            connect_timeout: 0,
            read_timeout_ms: 0,
            f_debug: 0,
            family: Family::Any,
            telnet_command: None,
            proxy_auth: ProxyAuthType::None,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    /// Default port for a given proxy method.
    pub fn default_port(method: ProxyMethod) -> u16 {
        match method {
            ProxyMethod::Socks => 1080,
            ProxyMethod::Http => 80,
            ProxyMethod::Telnet => 23,
            _ => 0,
        }
    }

    /// Default resolve mode for a SOCKS version.
    pub fn default_resolve(socks_version: u8) -> ResolveMode {
        match socks_version {
            5 => ResolveMode::Remote,
            4 => ResolveMode::Local,
            _ => ResolveMode::Remote,
        }
    }

    pub fn hold_session(&self) -> bool {
        self.f_hold_session
    }

    pub fn debug(&self) -> u8 {
        self.f_debug
    }
}
