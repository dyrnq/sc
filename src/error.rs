//! Crate-wide error type.

use std::io;

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors that can occur in `sc`.
///
/// Mirrors the failure modes of `connect.c`: protocol reply codes, HTTP status
/// codes, configuration problems, and I/O errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("config: {0}")]
    Config(String),

    #[error("auth: {0}")]
    Auth(&'static str),

    #[error("DNS: {0}")]
    Dns(String),

    #[error("SOCKS5 reply code 0x{0:02x}")]
    Socks5Reply(u8),

    #[error("SOCKS5 ATYP 0x{0:02x}")]
    Socks5Atyp(u8),

    #[error("SOCKS5: no auth method accepted")]
    Socks5NoAuth,

    #[error("SOCKS5: unsupported auth method 0x{0:02x}")]
    Socks5UnsupportedMethod(u8),

    #[error("SOCKS5 authentication failed")]
    Socks5AuthFailed,

    #[error("SOCKS4 reply code {0}")]
    Socks4Reply(u8),

    #[error("HTTP status {0}")]
    HttpStatus(u16),

    #[error("HTTP: {0}")]
    Http(&'static str),

    #[error("telnet: {0}")]
    Telnet(String),

    #[error("connect-NNN basename port invalid")]
    BadDefaultPort,

    #[error("unknown option: -{0}")]
    UnknownOption(char),

    #[error("usage: {0}")]
    Usage(String),

    #[error("not yet implemented: {0}")]
    Todo(&'static str),
}
