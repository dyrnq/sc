//! `sc` — ssh-connect: an OpenSSH `ProxyCommand` replacement.
//!
//! Phase 1 supports direct TCP connections only. SOCKS / HTTP / TELNET
//! proxies are wired up but return `Error::Todo` until later phases.

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

    // Phase 1: only DIRECT works end-to-end. Other methods parse but error
    // out of the proxy stub.
    if !matches!(cfg.relay_method, ProxyMethod::Direct) {
        return Err(Error::Todo(
            "non-DIRECT proxy methods are implemented in Phases 2-8",
        ));
    }

    // Open the connection.
    let mut stream = proxy::direct::connect(&cfg).await?;
    debug_message(&cfg);

    // Run the handshake (no-op for DIRECT).
    proxy::handshake(&mut stream, &mut cfg).await?;

    // Bidirectional relay between stdin/stdout and the remote socket.
    relay::relay_stdio(stream).await
}

/// Print the parsed configuration (matches `connect.c -d` debug output).
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
