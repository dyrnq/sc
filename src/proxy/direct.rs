//! Direct TCP connection (no proxy).
//!
//! Filled in by Phase 1.

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::Result;

/// Open a direct TCP connection to `dest_host:dest_port`. No handshake.
pub async fn connect(cfg: &Config) -> Result<TcpStream> {
    let addrs = crate::resolve::resolve_host(&cfg.dest_host, cfg.dest_port, cfg.family).await?;
    let stream = TcpStream::connect(addrs.as_slice()).await?;
    Ok(stream)
}
