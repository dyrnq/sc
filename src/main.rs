//! `sc` — ssh-connect: an OpenSSH `ProxyCommand` replacement.
//!
//! Phase 2: SOCKS5 (NOAUTH) added. Other proxy methods parse but error out.

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
        ProxyMethod::Socks | ProxyMethod::Http | ProxyMethod::Telnet => {
            // Phase 2: only Socks(NOAUTH) works.
            if !matches!(cfg.relay_method, ProxyMethod::Socks) {
                return Err(Error::Todo(
                    "HTTP/TELNET proxy methods are implemented in Phases 3/8",
                ));
            }
            proxy::connect_relay(&cfg).await?
        }
        ProxyMethod::Undecided => return Err(Error::Config("no proxy method".into())),
    };
    debug_message(&cfg);

    proxy::handshake(&mut stream, &mut cfg).await?;
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
