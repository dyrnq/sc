//! `sc` — ssh-connect: an OpenSSH `ProxyCommand` replacement.
//!
//! Phases 1-10: all proxy methods + listen + hold + direct-table bypass
//! (env entries and `-D` local-interface auto-add) + `-w` connect timeout.

use sc::{Result, cli, config::LocalType, conn_id, direct_table, proxy, relay};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // Read parameter files (/etc/connectrc, ~/.connectrc) before CLI
    // parsing — connect.c applies env-vars on top of the file table.
    // Per-file failures are reported via tracing::debug; this call is
    // infallible.
    sc::parameters::read_all();

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
    // Initialise the hickory DNS resolver (with -R override if set)
    // before any DNS lookup.
    if let Err(e) = sc::resolve::init(cfg.socks_ns) {
        tracing::error!("resolve::init: {e}");
    }

    // Initialise the direct-table bypass list from env vars and -D.
    init_direct_table(&cfg);

    // If the destination matches a direct-table entry, override the
    // proxy method to Direct. (Only meaningful when a proxy is set.)
    if cfg.relay_method != sc::config::ProxyMethod::Direct
        && direct_table::check_direct(&cfg.dest_host)
    {
        tracing::debug!(
            dest_host = %cfg.dest_host,
            "bypassing proxy (matched direct table)",
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

    debug_message(&cfg);

    // open_through_proxy honours cfg.connect_timeout for the initial TCP
    // connect (the `-w` flag) and runs the protocol handshake to the
    // end; the returned stream is ready for the relay.
    let stream = proxy::open_through_proxy(&cfg).await?;
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
/// (per-method) plus `-D` (auto-add local interface addresses). Keys are
/// routed through `parameters::getparam` so `.connectrc` is honoured.
fn init_direct_table(cfg: &sc::config::Config) {
    use sc::config::ProxyMethod;
    let key = match cfg.relay_method {
        ProxyMethod::Socks if cfg.socks_version == 5 => "SOCKS5_DIRECT",
        ProxyMethod::Socks => "SOCKS4_DIRECT",
        ProxyMethod::Http => "HTTP_DIRECT",
        ProxyMethod::Telnet | ProxyMethod::Direct | ProxyMethod::Undecided => "",
    };
    let mut entries: Vec<String> = Vec::new();
    if !key.is_empty()
        && let Some(s) = sc::parameters::getparam(key)
    {
        entries.extend(s.split(',').map(str::to_string));
    }
    if let Some(s) = sc::parameters::getparam("CONNECT_DIRECT") {
        entries.extend(s.split(',').map(str::to_string));
    }
    let auto = cfg.f_auto_direct;
    match direct_table::initialize(&entries, auto) {
        Ok(n) if n > 0 => tracing::debug!(entries = n, "direct table loaded"),
        Ok(_) => {}
        Err(e) => tracing::error!("direct table: {e}"),
    }
}

fn debug_message(cfg: &sc::config::Config) {
    tracing::debug!(
        relay_method = %cfg.relay_method.name(),
        ?cfg.relay_method,
        ?cfg.relay_host,
        relay_port = cfg.relay_port,
        dest_host = %cfg.dest_host,
        dest_port = cfg.dest_port,
        socks_version = cfg.socks_version,
        socks_resolve = %cfg.socks_resolve.name(),
        local_type = %cfg.local_type.name(),
        "configured",
    );
}
