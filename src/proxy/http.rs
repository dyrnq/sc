//! HTTP CONNECT handshake (Phase 3).

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::Result;

pub async fn begin(_stream: &mut TcpStream, _cfg: &mut Config) -> Result<()> {
    Err(crate::error::Error::Todo("HTTP CONNECT (Phase 3)"))
}
