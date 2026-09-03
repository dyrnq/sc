//! Proxy method dispatch.

pub mod direct;
pub mod http;
pub mod socks4;
pub mod socks5;
pub mod telnet;

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::Result;

/// Run the proxy handshake on an already-connected TCP stream.
///
/// Dispatches by `cfg.relay_method`. For SOCKS5/HTTP the stream may have been
/// connected to either the proxy host (and we hand off to the proxy) or, in
/// DIRECT mode, to the destination directly.
pub async fn handshake(stream: &mut TcpStream, cfg: &mut Config) -> Result<()> {
    use crate::config::ProxyMethod;
    match cfg.relay_method {
        ProxyMethod::Direct | ProxyMethod::Undecided => Ok(()),
        ProxyMethod::Socks => {
            if cfg.socks_version == 5 {
                socks5::begin(stream, cfg).await
            } else {
                socks4::begin(stream, cfg).await
            }
        }
        ProxyMethod::Http => http::begin(stream, cfg).await,
        ProxyMethod::Telnet => telnet::begin(stream, cfg).await,
    }
}
