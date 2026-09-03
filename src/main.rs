//! `sc` — ssh-connect: an OpenSSH `ProxyCommand` replacement.
//!
//! Phases 1-10: all proxy methods + listen + hold + direct-table bypass
//! (env entries and `-D` local-interface auto-add) + `-w` connect timeout.

use sc::{cli, config::LocalType, conn_id, direct_table, proxy, relay, Error, Result};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // Read parameter files (/etc/connectrc, ~/.connectrc) before CLI
    // parsing — connect.c applies env-vars on top of the file table.
    let _ = sc::parameters::read_all();

    let cfg = match cli::parse(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[fatal] {e}");
            std::process::exit(1);
        }
    };

    // Init tracing *after* parsing so `cfg.f_debug` can drive the level
    // (1 → debug, ≥2 → trace). `RUST_LOG` still wins if set, matching
    // the usual precedence. error-level events from parameter-file parsing
    // above are visible regardless of level.
    sc::log::init_tracing(cfg.f_debug);

    if let Err(e) = run(cfg).await {
        eprintln!("[fatal] {e}");
        std::process::exit(1);
    }
}

async fn run(mut cfg: sc::config::Config) -> Result<()> {
    // Apply -R resolver override before any DNS lookup.
    #[cfg(target_os = "linux")]
    if let Some(ns) = cfg.socks_ns {
        if let Err(e) = sc::switch_ns::apply(ns) {
            tracing::error!("switch_ns: {e}");
        }
    }

    // Initialise the direct-table bypass list from env vars and -D.
    init_direct_table(&cfg);

    // If the destination matches a direct-table entry, override the
    // proxy method to Direct. (Only meaningful when a proxy is set.)
    if cfg.relay_method != sc::config::ProxyMethod::Direct
        && direct_table::check_direct(&cfg.dest_host)
    {
        eprintln!(
            "DEBUG: bypassing proxy for {} (matched direct table)",
            cfg.dest_host
        );
        cfg.relay_method = sc::config::ProxyMethod::Direct;
        cfg.relay_host = None;
    }

    // Listen mode (-p / -P).
    if matches!(cfg.local_type, LocalType::Socket(_)) {
        return sc::listen::accept_loop(&cfg).await;
    }

    // Tag the one-shot stdio relay with a connection ID too, so its
    // log lines show up tagged identically to the listen path.
    let _conn = conn_id::span(conn_id::ConnectionId::next());

    use sc::config::ProxyMethod;

    let mut stream = match cfg.relay_method {
        ProxyMethod::Direct => open_with_timeout(&cfg, open_direct(&cfg)).await?,
        ProxyMethod::Socks => open_with_timeout(&cfg, open_relay_only(&cfg)).await?,
        ProxyMethod::Http => return http_with_retry(cfg).await,
        ProxyMethod::Telnet => {
            let mut s = open_with_timeout(&cfg, open_relay_only(&cfg)).await?;
            crate::proxy::telnet::begin(&mut s, &cfg).await?;
            return relay::relay_stdio(s, idle_timeout(&cfg)).await;
        }
        ProxyMethod::Undecided => return Err(Error::Config("no proxy method".into())),
    };
    debug_message(&cfg);

    proxy::handshake(&mut stream, &mut cfg).await?;
    relay::relay_stdio(stream, idle_timeout(&cfg)).await
}

/// Map `cfg.read_timeout_ms` to an `Option<Duration>` for the relay layer.
/// `0` → disabled, otherwise the configured window.
fn idle_timeout(cfg: &sc::config::Config) -> Option<Duration> {
    match cfg.read_timeout_ms {
        0 => None,
        ms => Some(Duration::from_millis(ms)),
    }
}

/// Initialise the direct-table bypass list from `*_DIRECT` env vars
/// (per-method) plus `-D` (auto-add local interface addresses).
fn init_direct_table(cfg: &sc::config::Config) {
    use sc::config::ProxyMethod;
    let key = match cfg.relay_method {
        ProxyMethod::Socks if cfg.socks_version == 5 => "SOCKS5_DIRECT",
        ProxyMethod::Socks => "SOCKS4_DIRECT",
        ProxyMethod::Http => "HTTP_DIRECT",
        ProxyMethod::Telnet | ProxyMethod::Direct | ProxyMethod::Undecided => "",
    };
    let mut entries: Vec<String> = Vec::new();
    if !key.is_empty() {
        if let Ok(s) = std::env::var(key) {
            entries.extend(s.split(',').map(str::to_string));
        }
    }
    if let Ok(s) = std::env::var("CONNECT_DIRECT") {
        entries.extend(s.split(',').map(str::to_string));
    }
    let auto = cfg.f_auto_direct;
    match direct_table::initialize(&entries, auto) {
        Ok(n) if n > 0 => eprintln!("DEBUG: direct table loaded {n} entries"),
        Ok(_) => {}
        Err(e) => tracing::error!("direct table: {e}"),
    }
}

/// Wrapper that applies `cfg.connect_timeout` (when set) to the open
/// future. Mirrors connect.c's SIGALRM.
async fn open_with_timeout<F>(cfg: &sc::config::Config, f: F) -> Result<tokio::net::TcpStream>
where
    F: std::future::Future<Output = Result<tokio::net::TcpStream>>,
{
    if cfg.connect_timeout > 0 {
        let secs = cfg.connect_timeout as u64;
        match tokio::time::timeout(Duration::from_secs(secs), f).await {
            Ok(r) => r,
            Err(_) => Err(Error::Config(format!("connect timeout after {secs}s"))),
        }
    } else {
        f.await
    }
}

async fn open_direct(cfg: &sc::config::Config) -> Result<tokio::net::TcpStream> {
    proxy::direct::connect(cfg).await
}

async fn open_relay_only(cfg: &sc::config::Config) -> Result<tokio::net::TcpStream> {
    proxy::connect_relay(cfg).await
}

/// HTTP CONNECT with redirect / auth-challenge retry. Mirrors the
/// `goto retry` pattern in `connect.c` (lines 3033-3037).
async fn http_with_retry(mut cfg: sc::config::Config) -> Result<()> {
    let mut stream = open_with_timeout(&cfg, open_relay_only(&cfg)).await?;
    debug_message(&cfg);
    loop {
        match proxy::http::begin(&mut stream, &mut cfg).await? {
            proxy::http::HttpStart::Ok => break,
            proxy::http::HttpStart::Retry => {
                drop(stream);
                stream = open_with_timeout(&cfg, open_relay_only(&cfg)).await?;
            }
        }
    }
    relay::relay_stdio(stream, idle_timeout(&cfg)).await
}

fn debug_message(cfg: &sc::config::Config) {
    eprintln!(
        "DEBUG: relay_method = {} ({:?}), relay_host={:?}, relay_port={}, \
         dest={}:{}, socks_version={}, socks_resolve={}, local_type={}",
        cfg.relay_method.name(),
        cfg.relay_method,
        cfg.relay_host,
        cfg.relay_port,
        cfg.dest_host,
        cfg.dest_port,
        cfg.socks_version,
        cfg.socks_resolve.name(),
        cfg.local_type.name(),
    );
}