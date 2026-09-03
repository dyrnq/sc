//! SOCKS5 greeting + method selection.
//!
//! Wire format:
//!
//! ```text
//! Greeting:     VER=5 | NMETHODS | METHODS...
//! Method reply: VER | METHOD      (METHOD=0xFF means none accepted)
//! ```

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// SOCKS5 auth method bytes (RFC 1928).
pub mod method {
    pub const NOAUTH: u8 = 0x00;
    pub const USERPASS: u8 = 0x02;
}

/// Send the greeting `VER=5 | NMETHODS | METHODS...` to the proxy.
///
/// Generic over `AsyncWrite + Unpin` so unit tests can drive it against
/// `tokio::io::duplex` instead of needing a real TCP listener.
pub async fn write_greeting<W>(stream: &mut W, methods: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let n = methods.len();
    if n > 255 {
        return Err(Error::Config("SOCKS5 too many auth methods".into()));
    }
    let mut buf = Vec::with_capacity(2 + n);
    buf.push(0x05); // VER
    buf.push(n as u8);
    buf.extend_from_slice(methods);
    stream.write_all(&buf).await?;
    Ok(())
}

/// Read the 2-byte method selection reply. Returns the chosen method, or
/// `Err(Socks5NoAuth)` if the server returned `0xFF` (none acceptable).
pub async fn read_method_reply<R>(stream: &mut R) -> Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        return Err(Error::Config(format!("SOCKS5 method reply VER={}", buf[0])));
    }
    if buf[1] == 0xFF {
        return Err(Error::Socks5NoAuth);
    }
    Ok(buf[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a greeting through a duplex pipe and assert the server side
    /// sees the exact bytes we wrote.
    #[tokio::test]
    async fn greeting_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64);

        // Server side: read greeting.
        let server = tokio::spawn(async move {
            let mut hdr = [0u8; 2];
            b.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr, [0x05, 0x02]);
            let mut methods = [0u8; 2];
            b.read_exact(&mut methods).await.unwrap();
            assert_eq!(methods, [method::NOAUTH, method::USERPASS]);
        });

        write_greeting(&mut a, &[method::NOAUTH, method::USERPASS])
            .await
            .unwrap();
        server.await.unwrap();
    }

    /// The reply is exactly 2 bytes; anything past the chosen method byte is
    /// the next protocol step, so the read must NOT swallow more.
    #[tokio::test]
    async fn reply_is_exactly_two_bytes() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let server = tokio::spawn(async move {
            b.write_all(&[0x05, method::NOAUTH]).await.unwrap();
            // The trailing byte must remain in the pipe for the next read.
            b.write_all(&[0xAA]).await.unwrap();
        });
        let chosen = read_method_reply(&mut a).await.unwrap();
        assert_eq!(chosen, method::NOAUTH);
        // Confirm the trailing byte is still there.
        let mut tail = [0u8; 1];
        a.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, [0xAA]);
        server.await.unwrap();
    }

    /// `0xFF` from the server means "no acceptable method" — surface that as
    /// a typed error rather than a generic Config error.
    #[tokio::test]
    async fn reply_ff_is_no_auth_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            b.write_all(&[0x05, 0xFF]).await.unwrap();
        });
        let err = read_method_reply(&mut a).await.unwrap_err();
        assert!(matches!(err, Error::Socks5NoAuth), "got {err:?}");
    }

    /// A reply with VER != 5 is malformed.
    #[tokio::test]
    async fn reply_bad_version_is_config_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            b.write_all(&[0x04, method::NOAUTH]).await.unwrap();
        });
        let err = read_method_reply(&mut a).await.unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }
}
