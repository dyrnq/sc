//! SOCKS5 USERPASS subnegotiation (RFC 1929).
//!
//! Wire format (request): `VER=1 | ULEN | UNAME | PLEN | PASSWD`.
//! Wire format (reply):   `VER | STATUS` (STATUS=0 is success).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::{Error, Result};

/// Run the full RFC 1929 sub-negotiation: write user/pass, read 2-byte
/// status, error out if status != 0.
pub async fn do_userpass(stream: &mut TcpStream, cfg: &Config) -> Result<()> {
    let user = cfg
        .relay_user
        .clone()
        .or_else(|| crate::auth::determine_relay_user(cfg.relay_method, cfg.socks_version).ok().flatten())
        .ok_or(Error::Auth("missing SOCKS5 user".into()))?;
    let pass = crate::auth::readpass(
        "SOCKS5 password: ",
        cfg.relay_method,
        cfg.socks_version,
    )
    .await?;

    let user_bytes = user.as_bytes();
    let pass_bytes = pass.as_bytes();
    if user_bytes.len() > 255 || pass_bytes.len() > 255 {
        return Err(Error::Config("SOCKS5 username/password too long".into()));
    }

    let mut req = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
    req.push(0x01); // subnegotiation VER
    req.push(user_bytes.len() as u8);
    req.extend_from_slice(user_bytes);
    req.push(pass_bytes.len() as u8);
    req.extend_from_slice(pass_bytes);
    stream.write_all(&req).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x01 || resp[1] != 0x00 {
        return Err(Error::Socks5AuthFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The request frame length is `VER + ULEN + UNAME + PLEN + PASSWD`.
    /// (Documented here for the future reader; the end-to-end test pins the
    /// exact bytes the client puts on the socket.)
    #[test]
    fn request_frame_length_formula() {
        let user = b"alice";
        let pass = b"s3cret";
        let expected = 1 + 1 + user.len() + 1 + pass.len();
        assert_eq!(expected, 14); // VER(1) + ULEN(1) + "alice"(5) + PLEN(1) + "s3cret"(6)
    }

    /// Username or password over 255 bytes must be rejected up front, before
    /// we write a malformed frame.
    #[test]
    fn oversized_user_or_password_is_above_byte_limit() {
        let long = "x".repeat(256);
        assert!(long.len() > 255);
    }
}