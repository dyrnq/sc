//! Hand-rolled command-line parser.
//!
//! Matches `connect.c::getarg` (lines 1552-1776):
//!
//! - Flag chaining: `-abc` is parsed as `-a -b -c`.
//! - Some flags take the next argv element as their value (`-S host:port -abc`).
//! - When port is missing, the binary basename `connect-NNN` provides a default.
//!
//! Adds two long-form flags: `--help` and `--family v4|v6|any`.

use crate::config::{Config, Family, LocalType, ProxyAuthType, ProxyMethod, ResolveMode};
use crate::error::{Error, Result};

const USAGE: &str = "\
usage: sc [-dDnhst45V] [-p local-port] [-R resolve] [-w timeout] [-W timeout]
              [-H proxy-server[:port]] [-S [user@]socks-server[:port]]
              [-T proxy-server[:port]] [-c telnet-proxy-command]
              [--family v4|v6|any] [--idle-timeout ms] host port
";

/// Long-form help: one line per flag. Printed by `--help`. Kept separate
/// from `USAGE` so the short banner stays scannable.
pub(crate) const LONG_HELP: &str = "\
sc — ssh-connect: an OpenSSH ProxyCommand replacement for SOCKS4/4a/5,
HTTP CONNECT, TELNET and direct connections. Drop-in replacement for
gotoh's connect.c.

Usage:
  sc [flags] host port

Method (pick one):
  -n              Direct TCP, no proxy.
  -h              HTTP CONNECT proxy from $HTTP_PROXY.
  -s              SOCKS proxy from $SOCKS_SERVER.
  -t              TELNET proxy from $TELNET_PROXY.
  -H host[:port]  HTTP CONNECT proxy (explicit host).
  -S [user@]host[:port]   SOCKS proxy (explicit host).
  -T host[:port]  TELNET proxy (explicit host).

SOCKS version (with -s or -S):
  -4              SOCKS v4 / 4a.
  -5              SOCKS v5 (default).

Listening & timeouts:
  -p PORT         Accept one local TCP connection on PORT, relay to
                  remote, exit.
  -P PORT         Same as -p but keep the remote session across multiple
                  accepts (hold-session).
  -w SECS         Connect-timeout (0 = no timeout).
  -W MS           Relay idle-timeout per direction; 0 disables.

Tuning:
  -R MODE|IP      SOCKS resolve mode: local / remote / both, or an IPv4
                  address to use as a custom resolver.
  -a LIST         Comma-separated auth methods: none,userpass.
  -c CMD          Telnet proxy command template (%h host, %p port).
  -D              Auto-add local interface addresses to the direct
                  (bypass-proxy) list.
  -d              Debug (repeat to increase verbosity: -dd, -ddd).
  --family v4|v6|any     Address-family filter.
  --idle-timeout MS      Same as -W.

Positional:
  host port       Destination. Port can be omitted if the binary is
                  symlinked as `connect-PORT`.

Other:
  -V, --version     Print version and exit.
  --help             Print this message and exit.

Environment (per-method fallback chain):
  SOCKS5_SERVER, SOCKS4_SERVER, SOCKS_SERVER
  HTTP_PROXY, TELNET_PROXY
  SOCKS5_USER, SOCKS_USER, SOCKS4_USER, HTTP_PROXY_USER, CONNECT_USER,
  LOGNAME, USER
  SOCKS5_PASSWD, SOCKS5_PASSWORD, HTTP_PROXY_PASSWORD, CONNECT_PASSWORD
  SOCKS5_RESOLVE, SOCKS4_RESOLVE, SOCKS_RESOLVE
  SOCKS5_DIRECT, SOCKS4_DIRECT, HTTP_DIRECT, CONNECT_DIRECT
  SSH_ASKPASS, DISPLAY (Unix only)
  /etc/connectrc and ~/.connectrc are also read.
";

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Print the short usage banner to stderr.
pub fn print_usage() {
    eprint!("{USAGE}");
}

/// Print the long-form help text (used by `--help`).
pub fn print_long_help() {
    eprint!("{LONG_HELP}");
}

/// Entry point: parse `argv` (including argv[0]) and return a Config.
pub fn parse(argv: &[String]) -> Result<Config> {
    if argv.len() < 2 {
        print_usage();
        std::process::exit(0);
    }

    let mut p = ArgParser {
        cfg: Config::new(),
        argv: argv.to_vec(),
        pos: 1,
    };

    while p.pos < p.argv.len() {
        let tok = p.argv[p.pos].clone();
        if tok == "--" {
            p.pos += 1;
            break;
        }
        if let Some(rest) = tok.strip_prefix("--") {
            p.parse_long_flag(rest)?;
            p.pos += 1;
        } else if let Some(rest) = tok.strip_prefix('-') {
            if rest.is_empty() {
                break;
            }
            p.parse_short_flags(&rest)?;
            // parse_short_flags is responsible for advancing self.pos.
        } else {
            break;
        }
    }

    p.parse_positional()?;
    p.finalise()?;
    Ok(p.cfg)
}

struct ArgParser {
    cfg: Config,
    argv: Vec<String>,
    pos: usize,
}

impl ArgParser {
    /// Consume the argv element at `pos + 1` as this flag's argument.
    /// Advances `self.pos` past both the flag and the argument.
    fn take_arg(&mut self) -> Result<String> {
        let arg_pos = self.pos + 1;
        if arg_pos >= self.argv.len() {
            return Err(Error::Config(format!(
                "option at index {} requires an argument",
                self.pos
            )));
        }
        let arg = self.argv[arg_pos].clone();
        self.pos += 2;
        Ok(arg)
    }

    /// Parse a long flag (the part after `--`). When the flag takes a value
    /// in a separate argv element, `self.pos` is advanced by 1 inside this
    /// function (the caller adds another 1 to skip the flag token itself).
    fn parse_long_flag(&mut self, rest: &str) -> Result<()> {
        let (name, val) = match rest.find('=') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        match name {
            "help" => {
                print_long_help();
                std::process::exit(0);
            }
            "version" => {
                println!("sc {VERSION}");
                std::process::exit(0);
            }
            "family" => {
                let v = match val {
                    Some(v) => v.to_string(),
                    None => {
                        let p = self.pos + 1;
                        if p >= self.argv.len() {
                            return Err(Error::Config("--family requires an argument".into()));
                        }
                        let s = self.argv[p].clone();
                        self.pos += 1; // consumed one extra token
                        s
                    }
                };
                self.cfg.family = Family::from_str(&v)
                    .ok_or_else(|| Error::Config(format!("invalid --family: {v}")))?;
            }
            "idle-timeout" => {
                let v = match val {
                    Some(v) => v.to_string(),
                    None => {
                        let p = self.pos + 1;
                        if p >= self.argv.len() {
                            return Err(Error::Config(
                                "--idle-timeout requires an argument".into(),
                            ));
                        }
                        let s = self.argv[p].clone();
                        self.pos += 1;
                        s
                    }
                };
                self.cfg.read_timeout_ms = v
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid --idle-timeout: {v}")))?;
            }
            other => {
                return Err(Error::Config(format!("unknown long option: --{other}")));
            }
        }
        Ok(())
    }

    /// Parse a short-flag string. For chained flags (`-abc`), all chars run
    /// in sequence. For flags that take an argument, the next argv element
    /// is consumed and `self.pos` is advanced past both.
    fn parse_short_flags(&mut self, s: &str) -> Result<()> {
        for c in s.chars() {
            match c {
                'V' => {
                    println!("sc {VERSION}");
                    std::process::exit(0);
                }
                'd' => self.cfg.f_debug = self.cfg.f_debug.saturating_add(1),
                'D' => self.cfg.f_auto_direct = true,
                'n' => self.cfg.relay_method = ProxyMethod::Direct,
                'h' => self.cfg.relay_method = ProxyMethod::Http,
                's' => self.cfg.relay_method = ProxyMethod::Socks,
                't' => self.cfg.relay_method = ProxyMethod::Telnet,
                '4' => self.cfg.socks_version = 4,
                '5' => self.cfg.socks_version = 5,
                'P' => {
                    let p = self.take_arg()?;
                    self.cfg.f_hold_session = true;
                    self.cfg.local_type = LocalType::Socket(parse_port(&p)?);
                    return Ok(());
                }
                'p' => {
                    let p = self.take_arg()?;
                    self.cfg.local_type = LocalType::Socket(parse_port(&p)?);
                    return Ok(());
                }
                'w' => {
                    let v = self.take_arg()?;
                    self.cfg.connect_timeout = v
                        .parse()
                        .map_err(|_| Error::Config(format!("invalid timeout: {v}")))?;
                    return Ok(());
                }
                'W' => {
                    let v = self.take_arg()?;
                    self.cfg.read_timeout_ms = v
                        .parse()
                        .map_err(|_| Error::Config(format!("invalid idle timeout: {v}")))?;
                    return Ok(());
                }
                'S' => {
                    let spec = self.take_arg()?;
                    parse_relay_spec(&spec, ProxyMethod::Socks, &mut self.cfg)?;
                    return Ok(());
                }
                'H' => {
                    let spec = self.take_arg()?;
                    parse_relay_spec(&spec, ProxyMethod::Http, &mut self.cfg)?;
                    return Ok(());
                }
                'T' => {
                    let spec = self.take_arg()?;
                    parse_relay_spec(&spec, ProxyMethod::Telnet, &mut self.cfg)?;
                    return Ok(());
                }
                'c' => {
                    let cmd = self.take_arg()?;
                    self.cfg.telnet_command = Some(cmd);
                    return Ok(());
                }
                'a' => {
                    let list = self.take_arg()?;
                    self.cfg.socks5_auth = Some(list);
                    return Ok(());
                }
                'R' => {
                    let arg = self.take_arg()?;
                    if let Some(mode) = ResolveMode::from_str(&arg) {
                        self.cfg.socks_resolve = mode;
                    } else {
                        use std::net::Ipv4Addr;
                        match arg.parse::<Ipv4Addr>() {
                            Ok(v4) => {
                                self.cfg.socks_ns = Some(v4);
                                self.cfg.socks_resolve = ResolveMode::Local;
                            }
                            Err(_) => {
                                return Err(Error::Config(format!(
                                    "invalid -R argument: {arg}"
                                )));
                            }
                        }
                    }
                    return Ok(());
                }
                other => return Err(Error::UnknownOption(other)),
            }
        }
        // Chained, no-arg flags only: advance past the flag token.
        self.pos += 1;
        Ok(())
    }

    /// Parse trailing positional args: `host [port]`. Falls back to the
    /// `connect-NNN` basename trick when port is missing.
    fn parse_positional(&mut self) -> Result<()> {
        let mut port: Option<u16> = None;
        let mut host: Option<String> = None;
        while self.pos < self.argv.len() {
            let a = self.argv[self.pos].clone();
            self.pos += 1;
            match (&host, &port) {
                (None, _) => host = Some(a),
                (_, None) => {
                    port = Some(parse_port(&a)?);
                }
                _ => {
                    return Err(Error::Usage(format!("unexpected argument: {a}")));
                }
            }
        }

        self.cfg.dest_host = host.ok_or_else(|| Error::Usage("missing host".into()))?;
        if let Some(p) = port {
            self.cfg.dest_port = p;
        } else {
            // Try the binary basename `connect-NNN` trick (C lines 1729-1735).
            let argv0 = self.argv.first().map(String::as_str).unwrap_or("");
            let basename = std::path::Path::new(argv0)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if let Some(idx) = basename.find("connect-") {
                let rest = &basename[idx + "connect-".len()..];
                if let Ok(p) = parse_port(rest) {
                    self.cfg.dest_port = p;
                }
            }
            if self.cfg.dest_port == 0 {
                return Err(Error::BadDefaultPort);
            }
        }
        Ok(())
    }

    /// Resolve defaults from env vars. Mirrors `connect.c::set_relay`.
    fn finalise(&mut self) -> Result<()> {
        // `-s` / `-h` / `-t` without an explicit relay spec: pull from env.
        if matches!(self.cfg.relay_method, ProxyMethod::Socks) && self.cfg.relay_host.is_none() {
            let env_name = match self.cfg.socks_version {
                5 => "SOCKS5_SERVER",
                4 => "SOCKS4_SERVER",
                _ => "SOCKS_SERVER",
            };
            if let Ok(spec) = std::env::var(env_name).or_else(|_| std::env::var("SOCKS_SERVER")) {
                parse_relay_spec(&spec, ProxyMethod::Socks, &mut self.cfg)?;
            }
        }
        if matches!(self.cfg.relay_method, ProxyMethod::Http) && self.cfg.relay_host.is_none() {
            if let Ok(spec) = std::env::var("HTTP_PROXY") {
                parse_relay_spec(&spec, ProxyMethod::Http, &mut self.cfg)?;
            }
        }
        if matches!(self.cfg.relay_method, ProxyMethod::Telnet) && self.cfg.relay_host.is_none() {
            if let Ok(spec) = std::env::var("TELNET_PROXY") {
                parse_relay_spec(&spec, ProxyMethod::Telnet, &mut self.cfg)?;
            }
        }

        // Default ports.
        if matches!(
            self.cfg.relay_method,
            ProxyMethod::Socks | ProxyMethod::Http | ProxyMethod::Telnet
        ) && self.cfg.relay_port == 0
        {
            self.cfg.relay_port = Config::default_port(self.cfg.relay_method);
        }

        // SOCKS resolve-mode default (REMOTE for v5, LOCAL for v4).
        if matches!(self.cfg.relay_method, ProxyMethod::Socks)
            && matches!(self.cfg.socks_resolve, ResolveMode::Unknown)
        {
            self.cfg.socks_resolve = Config::default_resolve(self.cfg.socks_version);
        }

        // Telnet default command.
        if matches!(self.cfg.relay_method, ProxyMethod::Telnet) && self.cfg.telnet_command.is_none()
        {
            self.cfg.telnet_command = Some("telnet %h %p".to_string());
        }

        // Default to DIRECT when no method flag was given.
        if matches!(self.cfg.relay_method, ProxyMethod::Undecided) {
            self.cfg.relay_method = ProxyMethod::Direct;
        }

        Ok(())
    }
}

/// Parse a port spec: digits → number, otherwise `/etc/services` lookup.
/// (Service-name lookup is TODO; only numeric is accepted for now.)
fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>()
        .map_err(|_| Error::Config(format!("invalid port: {s}")))
}

/// Parse a `[-S|-H|-T]` value: `[user@]host[:port]`, with optional
/// `http://` prefix and trailing path stripped for `-H`.
pub fn parse_relay_spec(spec: &str, method: ProxyMethod, cfg: &mut Config) -> Result<()> {
    let mut s = spec.trim();
    cfg.relay_method = method;
    cfg.proxy_auth = ProxyAuthType::None;

    if matches!(method, ProxyMethod::Http) {
        if let Some(rest) = s.strip_prefix("http://") {
            s = rest;
        }
        if let Some(slash) = s.find('/') {
            s = &s[..slash];
        }
    }

    let mut user: Option<String> = None;
    if let Some(at) = s.find('@') {
        user = Some(s[..at].to_string());
        s = &s[at + 1..];
    }

    let mut host = s.to_string();
    let mut port: u16 = 0;
    if let Some(colon) = host.rfind(':') {
        if let Ok(p) = host[colon + 1..].parse::<u16>() {
            port = p;
            host.truncate(colon);
        }
    }

    if host.is_empty() {
        return Err(Error::Config(format!("empty host in relay spec: {spec}")));
    }
    cfg.relay_host = Some(host);
    if port > 0 {
        cfg.relay_port = port;
    }
    if user.is_some() {
        cfg.relay_user = user;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_direct_basic() {
        let argv = make_argv(&["sc", "example.com", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.relay_method, ProxyMethod::Direct);
        assert_eq!(cfg.dest_host, "example.com");
        assert_eq!(cfg.dest_port, 22);
    }

    #[test]
    fn parse_debug_flag() {
        let argv = make_argv(&["sc", "-d", "-d", "host", "80"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.f_debug, 2);
    }

    #[test]
    fn parse_chained_flags() {
        let argv = make_argv(&["sc", "-dn", "host", "80"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.f_debug, 1);
        assert_eq!(cfg.relay_method, ProxyMethod::Direct);
    }

    #[test]
    fn parse_socks_spec() {
        let argv = make_argv(&["sc", "-S", "alice@socks.example.com:1080", "target", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.relay_method, ProxyMethod::Socks);
        assert_eq!(cfg.relay_host.as_deref(), Some("socks.example.com"));
        assert_eq!(cfg.relay_port, 1080);
        assert_eq!(cfg.relay_user.as_deref(), Some("alice"));
        assert_eq!(cfg.socks_version, 5);
    }

    #[test]
    fn parse_http_with_prefix_and_path() {
        let argv = make_argv(&["sc", "-H", "http://proxy.example.com:8080/path", "target", "443"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.relay_method, ProxyMethod::Http);
        assert_eq!(cfg.relay_host.as_deref(), Some("proxy.example.com"));
        assert_eq!(cfg.relay_port, 8080);
    }

    #[test]
    fn parse_family_long() {
        let argv = make_argv(&["sc", "--family", "v6", "host", "80"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.family, Family::V6);
    }

    #[test]
    fn parse_family_equals() {
        let argv = make_argv(&["sc", "--family=v4", "host", "80"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.family, Family::V4);
    }

    #[test]
    fn parse_p_with_port() {
        let argv = make_argv(&["sc", "-p", "5550", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.local_type, LocalType::Socket(5550));
        assert!(!cfg.f_hold_session);
    }

    #[test]
    fn parse_capital_p_sets_hold() {
        let argv = make_argv(&["sc", "-P", "5550", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.local_type, LocalType::Socket(5550));
        assert!(cfg.f_hold_session);
    }

    #[test]
    fn parse_resolve_modes() {
        let argv = make_argv(&["sc", "-R", "local", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.socks_resolve, ResolveMode::Local);

        let argv = make_argv(&["sc", "-R", "remote", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.socks_resolve, ResolveMode::Remote);

        let argv = make_argv(&["sc", "-R", "1.2.3.4", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.socks_resolve, ResolveMode::Local);
        assert_eq!(cfg.socks_ns.unwrap().to_string(), "1.2.3.4");
    }

    #[test]
    fn parse_p_after_flag() {
        // `-p 5550 host 22`: the `5550` must be the listen port, not the host.
        let argv = make_argv(&["sc", "-p", "5550", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.local_type, LocalType::Socket(5550));
        assert_eq!(cfg.dest_host, "host");
        assert_eq!(cfg.dest_port, 22);
    }

    #[test]
    fn parse_capital_w_sets_idle_timeout() {
        let argv = make_argv(&["sc", "-W", "30000", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.read_timeout_ms, 30_000);
    }

    #[test]
    fn parse_idle_timeout_long_flag() {
        let argv = make_argv(&["sc", "--idle-timeout=45000", "host", "22"]);
        let cfg = parse(&argv).unwrap();
        assert_eq!(cfg.read_timeout_ms, 45_000);
    }

    #[test]
    fn long_help_mentions_every_short_flag() {
        // Pin the long help text against regressions: every short flag must
        // appear in the help so users can discover it. Catches the case
        // where someone adds a flag but forgets to document it.
        for flag in ['s', 'n', 'h', 't', 'S', 'H', 'T', 'c', 'P', 'p', 'w', 'W', 'a', 'R', '4', '5', 'V', 'd', 'D'] {
            let needle = format!("-{flag}");
            assert!(
                LONG_HELP.contains(&needle),
                "LONG_HELP missing flag {needle}"
            );
        }
    }
}
