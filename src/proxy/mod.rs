//! Proxy method dispatch.

pub mod direct;
pub mod http;
pub mod socks4;
pub mod socks5;
pub mod telnet;

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::Result;

/// Connect to `relay_host:relay_port` (the proxy server). For DIRECT mode
/// the relay host is unset and this returns an error.
pub async fn connect_relay(cfg: &Config) -> Result<TcpStream> {
    let host = cfg
        .relay_host
        .as_deref()
        .ok_or_else(|| crate::error::Error::Config("no relay host set".into()))?;
    let addrs = crate::resolve::resolve_host(host, cfg.relay_port, cfg.family).await?;
    let stream = TcpStream::connect(addrs.as_slice()).await?;
    Ok(stream)
}

/// Run the proxy handshake on an already-connected TCP stream.
///
/// HTTP CONNECT has its own retry loop (302 / 401 / 407), so callers should
/// dispatch Http explicitly via `http::begin` rather than this dispatcher.
pub async fn handshake(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    use crate::config::ProxyMethod;
    match cfg.relay_method {
        ProxyMethod::Direct | ProxyMethod::Undecided | ProxyMethod::Http => Ok(()),
        ProxyMethod::Socks => {
            if cfg.socks_version == 5 {
                socks5::begin(stream, cfg).await
            } else {
                socks4::begin(stream, cfg).await
            }
        }
        ProxyMethod::Telnet => telnet::begin(stream, cfg).await,
    }
}
