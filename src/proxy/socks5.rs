//! SOCKS v5 handshake (Phases 2 + 4).

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::Result;

pub async fn begin(_stream: &mut TcpStream, _cfg: &mut Config) -> Result<()> {
    Err(crate::error::Error::Todo("SOCKS5 (Phase 2)"))
}
