//! SOCKS v4 / v4a handshake (Phase 7).

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::Result;

pub async fn begin(_stream: &mut TcpStream, _cfg: &mut Config) -> Result<()> {
    Err(crate::error::Error::Todo("SOCKS4/4a (Phase 7)"))
}
