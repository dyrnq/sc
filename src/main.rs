//! `sc` — ssh-connect: an OpenSSH `ProxyCommand` replacement.
//!
//! Phase 3: HTTP CONNECT (with 302 redirect retry). SOCKS5 NOAUTH also live.

use sc::{cli, config::LocalType, proxy, relay, Error, Result};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    sc::log::init_tracing();

    let argv: Vec<String> = std::env::args().collect();
    let cfg = match cli::parse(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[fatal] {e}");
            std::process::exit(1);
        }
    };

    if matches!(cfg.local_type, LocalType::Socket(_)) {
        eprintln!("[fatal] listen mode (-p/-P) is not implemented yet");
        std::process::exit(1);
    }

    if let Err(e) = run(cfg).await {
        eprintln!("[fatal] {e}");
        std::process::exit(1);
    }
}

async fn run(mut cfg: sc::config::Config) -> Result<()> {
    use sc::config::ProxyMethod;

    let mut stream = match cfg.relay_method {
        ProxyMethod::Direct => proxy::direct::connect(&cfg).await?,
        ProxyMethod::Socks => {
            // SOCKS5 only; SOCKS4 in Phase 7.
            if cfg.socks_version != 5 {
                return Err(Error::Todo("SOCKS4/4a (Phase 7)"));
            }
            proxy::connect_relay(&cfg).await?
        }
        ProxyMethod::Http => {
            // HTTP CONNECT with 302 / 401 / 407 retry loop.
            return http_with_retry(cfg).await;
        }
        ProxyMethod::Telnet => {
            return Err(Error::Todo("TELNET proxy (Phase 8)"));
        }
        ProxyMethod::Undecided => return Err(Error::Config("no proxy method".into())),
    };
    debug_message(&cfg);

    proxy::handshake(&mut stream, &mut cfg).await?;
    relay::relay_stdio(stream).await
}

/// HTTP CONNECT with redirect / auth-challenge retry. Mirrors the
/// `goto retry` pattern in `connect.c` (lines 3033-3037).
async fn http_with_retry(mut cfg: sc::config::Config) -> Result<()> {
    let mut stream = proxy::connect_relay(&cfg).await?;
    debug_message(&cfg);
    loop {
        match proxy::http::begin(&mut stream, &mut cfg).await? {
            proxy::http::HttpStart::Ok => break,
            proxy::http::HttpStart::Retry => {
                // Drop the old connection, reconnect to the (possibly updated)
                // relay_host:relay_port.
                drop(stream);
                stream = proxy::connect_relay(&cfg).await?;
            }
        }
    }
    relay::relay_stdio(stream).await
}

fn debug_message(cfg: &sc::config::Config) {
    eprintln!(
        "DEBUG: relay_method = {} ({:?}), relay_host={:?}, relay_port={}, \
         socks_version={}, socks_resolve={}, local_type={}",
        cfg.relay_method.name(),
        cfg.relay_method,
        cfg.relay_host,
        cfg.relay_port,
        cfg.socks_version,
        cfg.socks_resolve.name(),
        cfg.local_type.name(),
    );
}
