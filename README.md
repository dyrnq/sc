# sc — ssh-connect (Rust)

A drop-in replacement for gotoh's [`connect.c`](../ssh-connect/connect.c) used as
OpenSSH `ProxyCommand`. Forwards stdin/stdout (or a local TCP socket) to a
TCP destination reached through a SOCKS4/4a/5, HTTP CONNECT, or TELNET proxy.

Built in Rust on top of Tokio. Currently Linux + macOS first; Windows support
is being added incrementally.

## Why

`connect.c` is a 3085-line single-file C program that handles five TCP
forwarding protocols and runs as OpenSSH's `ProxyCommand`. `sc` is a
from-scratch reimplementation in Rust that preserves the wire-level
behaviour and CLI quirks (so existing `~/.ssh/config` lines and shell
scripts keep working) but uses async I/O, structured errors, and a
modular layout.

## CLI (1:1 with `connect.c`)

```
usage: sc [-dDnhst45V] [-p local-port] [-R resolve] [-w timeout]
              [-H proxy-server[:port]] [-S [user@]socks-server[:port]]
              [-T proxy-server[:port]] [-c telnet-proxy-command]
              [--family v4|v6|any] host port
```

`-P` is an alias for `-p` that also sets `f_hold_session`.

Long flags are limited to `--help`, `--version`, and `--family v4|v6|any`
to keep the CLI 1:1-compatible with `connect.c`.

### Notable quirks preserved from connect.c

- **Flag chaining**: `-abc` is parsed as `-a -b -c`.
- **Argument-consuming flags can be followed by other flags**: `-S
  host:port -abc` works.
- **Binary basename `connect-NNN`**: when `port` is missing, the default
  is taken from the binary filename (e.g. `connect-ssh` → 22).
- **`-P` falls through to `-p`** and sets hold-session.
- **`-R <dotted-IPv4>`**: replaces the resolver's nameserver list with the
  given IPv4 (Linux only — uses glibc's `__res_state`).
- **`-D`**: enumerates local network interfaces and adds their
  `addr/mask` to the direct table, so traffic to those subnets bypasses
  the proxy.

## Examples

```sh
# Direct TCP
sc example.com 22

# SOCKS5 (default version)
sc -S proxy.local:1080 internal.example.com 443

# SOCKS5 with username/password
SOCKS5_USER=alice SOCKS5_PASSWD=secret \
  sc -S user@proxy.local:1080 internal.example.com 22

# HTTP CONNECT proxy with auth
HTTP_PROXY_USER=alice HTTP_PROXY_PASSWORD=secret \
  sc -H proxy.local:3128 internal.example.com 22

# TELNET proxy with custom command
sc -T telnet-gw.local:23 -c 'open %h %p' internal.example.com 22

# Listen mode — sc accepts local TCP connections and relays through the proxy
sc -p 1080 -S proxy.local:1080 internal.example.com 22
# Now point ssh at it:
# ssh -o 'ProxyCommand=nc -X connect -x localhost:1080 %h %p' user@internal

# Hold-session: same remote tunnel across multiple local connects
sc -P 1080 -S proxy.local:1080 internal.example.com 22

# Add local networks (RFC1918) to the bypass list
sc -D -S proxy.local:1080 internal.example.com 22

# Connect timeout (matches connect.c's SIGALRM)
sc -w 5 -S proxy.local:1080 internal.example.com 22

# Use a custom nameserver
sc -R 10.0.0.1 -S proxy.local:1080 internal.example.com 22

# Read ~/.connectrc for default SOCKS5 proxy + user/password
cat ~/.connectrc <<EOF
socks5_server = proxy.local:1080
socks5_user   = alice
socks5_passwd = secret
EOF
sc internal.example.com 22
```

## Build

```sh
cargo build --release
# Binary at target/release/sc
```

Dependencies (declared in `Cargo.toml`): `tokio`, `thiserror`, `base64`,
`tracing`, `tracing-subscriber`, `libc`. Unix-only: `nix`, `signal-hook`.
Windows-only: `windows-sys`. The `switch_ns` resolver override uses a
18-line C shim (`csrc/switch_ns_shim.c`) compiled via the `cc` crate.

## Module layout

```
src/
├── auth.rs          password acquisition (env → SSH_ASKPASS → /dev/tty)
├── cli.rs           hand-rolled CLI parser (matches connect.c quirks)
├── config.rs        Config struct + method enums
├── direct_table.rs  bypass-proxy table (CIDR + domain; -D auto-fill)
├── error.rs         thiserror enum
├── lib.rs           crate root
├── listen.rs        -p / -P listen loop
├── log.rs           debug!/error!/fatal! macros
├── parameters.rs    /etc/connectrc + ~/.connectrc
├── proxy/
│   ├── direct.rs    plain TCP connect
│   ├── http.rs      HTTP CONNECT (302 redirect + 401/407 Basic auth)
│   ├── mod.rs       dispatch
│   ├── socks4.rs    SOCKS4 / SOCKS4a
│   ├── socks5.rs   SOCKS5 (NOAUTH + USERPASS, IPv4/IPv6/DOMAINNAME)
│   └── telnet.rs    TELNET (-c template expansion)
├── relay.rs         EOF-asymmetric bidirectional relay
├── resolve.rs       DNS lookup_host with --family filter
├── switch_ns.rs     glibc -R <IPv4> override (Linux only)
└── tty.rs           no-echo terminal read (Unix termios / Windows Console)

csrc/
└── switch_ns_shim.c  C wrapper for the versioned _res@GLIBC_2.2.5 symbol
```

## Status

All 12 phases from `melodic-sparking-wombat.md` are complete:

| # | Phase | State |
|---|-------|-------|
| 1 | CLI + Config + Direct + stdin/stdout relay | ✅ |
| 2 | SOCKS5 NOAUTH | ✅ |
| 3 | HTTP CONNECT (no auth) | ✅ |
| 4 | SOCKS5 USERPASS + env password | ✅ |
| 5 | TTY password read | ✅ |
| 6 | SSH_ASKPASS invocation | ✅ |
| 7 | SOCKS4 / SOCKS4a | ✅ |
| 8 | TELNET proxy | ✅ |
| 9 | `-p` listen + `-P` hold-session | ✅ |
| 10 | `-w` timeout + `-D` direct table | ✅ |
| 11 | `-R` switch_ns (Linux) + parameter files | ✅ |
| 12 | Polish + README + tests | ✅ |

37 unit tests cover the CLI parser, SOCKS4/4a/5 wire formats, HTTP
CONNECT status parsing, TELNET template expansion, SSH_ASKPASS
invocation, the parameter-file parser, and the direct-table parser.

End-to-end smoke verified:

- `sc -p 8888 -n 127.0.0.1 7777` relays bytes through a Python echo
  server.
- `sc -D -S unreachable 127.0.0.1 22` enumerates 7 interfaces and
  bypasses the proxy because `127.0.0.1` matches `lo`'s `/8`.
- `sc -w 1 -S unreachable example.com 22` aborts with
  "connect timeout after 1s".
- `sc -R 8.8.8.8 -S unreachable example.com 22` prints
  "switch_ns using nameserver 8.8.8.8".
- `connect-22 127.0.0.1` (no port arg) correctly uses port 22.

## Out of scope (for now)

- Windows `GetAdaptersAddresses` enumeration of local interfaces for `-D`
  (currently Linux + macOS via `getifaddrs`; Windows is a no-op stub).
- Per-token parsing for the direct table `Domain` entries: `check_direct`
  currently matches CIDR against numeric IPs; hostname matching is wired
  but only exercised by tests.
- IPv6 for `-R switch_ns` (only IPv4 in connect.c too).

## License

Same terms as the original `connect.c` (BSD-style).