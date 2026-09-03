//! SOCKS5 CONNECT request + reply.
//!
//! Wire formats:
//!
//! ```text
//! CONNECT request: VER=5 | CMD=1 | RSV=0 | ATYP | DST.ADDR | DST.PORT(2 BE)
//! CONNECT reply:   VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
//! ```
//!
//! `ATYP`: `0x01` IPv4 (4 bytes), `0x03` DOMAINNAME (1-byte-len + name),
//! `0x04` IPv6 (16 bytes).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::Config;
use crate::error::{Error, Result};

/// SOCKS5 address types.
pub mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAINNAME: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

/// Write the CONNECT request. ATYP is chosen from `cfg.dest_host`:
/// numeric IPv4 / IPv6 short-circuit, otherwise DOMAINNAME.
pub async fn write_connect<W>(stream: &mut W, cfg: &mut Config) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    super::maybe_resolve_destination(cfg).await?;

    let host = cfg.dest_host.clone();
    let port = cfg.dest_port;
    let mut req = Vec::with_capacity(32);
    req.push(0x05); // VER
    req.push(0x01); // CMD = CONNECT
    req.push(0x00); // RSV

    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(atyp::IPV4);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(atyp::IPV6);
        req.extend_from_slice(&v6.octets());
    } else {
        // Domain name.
        if host.len() > 255 {
            return Err(Error::Config(format!(
                "SOCKS5 destination hostname too long: {host}"
            )));
        }
        req.push(atyp::DOMAINNAME);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }

    req.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&req).await?;
    Ok(())
}

/// Read the CONNECT reply: 4-byte header (VER, REP, RSV, ATYP), then the
/// variable-length BND.ADDR tail (4 / 1+N+2 / 16 bytes depending on ATYP),
/// then the 2-byte BND.PORT. We only check the header; the tail is consumed
/// and discarded.
pub async fn read_connect_reply<R>(stream: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(Error::Config(format!("SOCKS5 reply VER={}", hdr[0])));
    }
    if hdr[1] != 0x00 {
        return Err(Error::Socks5Reply(hdr[1]));
    }
    let tail_len = match hdr[3] {
        atyp::IPV4 => 4 + 2,
        atyp::DOMAINNAME => {
            // We already read the 1-byte LEN above; remaining bytes are
            // LEN bytes of name + 2 bytes of port.
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        atyp::IPV6 => 16 + 2,
        a => return Err(Error::Socks5Atyp(a)),
    };
    let mut sink = vec![0u8; tail_len];
    stream.read_exact(&mut sink).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reply with REP != 0 must surface as `Error::Socks5Reply(rep)`.
    #[tokio::test]
    async fn reply_with_nonzero_rep_errors() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // VER=5, REP=2 (connection not allowed by ruleset), RSV=0, ATYP=IPv4,
        // 0.0.0.0:0 — fake success-with-no-bind tail is fine because REP
        // short-circuits.
        tokio::spawn(async move {
            b.write_all(&[0x05, 0x02, 0x00, atyp::IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = read_connect_reply(&mut a).await.unwrap_err();
        assert!(matches!(err, Error::Socks5Reply(0x02)), "got {err:?}");
    }

    /// Unknown ATYP in the reply is a typed error.
    #[tokio::test]
    async fn reply_unknown_atyp_errors() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            b.write_all(&[0x05, 0x00, 0x00, 0x99]).await.unwrap();
        });
        let err = read_connect_reply(&mut a).await.unwrap_err();
        assert!(matches!(err, Error::Socks5Atyp(0x99)), "got {err:?}");
    }

    /// DOMAINNAME ATYP must read the variable-length name tail before the
    /// 2-byte port. Pin the exact bytes consumed.
    #[tokio::test]
    async fn reply_domainname_consumes_variable_tail() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // name = "x", port = 1080 → tail = 1 (len) + 1 (name) + 2 (port) = 4.
        tokio::spawn(async move {
            b.write_all(&[0x05, 0x00, 0x00, atyp::DOMAINNAME, 1, b'x', 0x04, 0x38])
                .await
                .unwrap();
            // Trailing byte must remain after read_connect_reply returns.
            b.write_all(&[0xAA]).await.unwrap();
        });
        read_connect_reply(&mut a).await.unwrap();
        let mut tail = [0u8; 1];
        a.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, [0xAA]);
    }

    /// IPv4 ATYP: tail = 4 addr + 2 port = 6 bytes. Pin the consumed length.
    #[tokio::test]
    async fn reply_ipv4_consumes_six_tail_bytes() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            b.write_all(&[0x05, 0x00, 0x00, atyp::IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            b.write_all(&[0xBB]).await.unwrap();
        });
        read_connect_reply(&mut a).await.unwrap();
        let mut tail = [0u8; 1];
        a.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, [0xBB]);
    }

    /// IPv6 ATYP: tail = 16 addr + 2 port = 18 bytes.
    #[tokio::test]
    async fn reply_ipv6_consumes_eighteen_tail_bytes() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let mut frame = vec![0x05, 0x00, 0x00, atyp::IPV6];
            frame.extend(std::iter::repeat(0u8).take(16)); // 16-byte addr
            frame.extend_from_slice(&[0, 0]); // port
            frame.push(0xCC); // sentinel
            b.write_all(&frame).await.unwrap();
        });
        read_connect_reply(&mut a).await.unwrap();
        let mut tail = [0u8; 1];
        a.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, [0xCC]);
    }
}