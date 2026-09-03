//! Bidirectional byte relay between a local side (stdin/stdout or local TCP)
//! and a remote TCP socket.
//!
//! EOF semantics mirror `connect.c::do_repeater`:
//!
//! - Remote EOF → both directions close. (No half-close to the local writer.)
//! - Local EOF → `shutdown(remote, SHUT_WR)` to send a FIN to the peer, and
//!   continue draining `remote → local` until the remote side also EOFs.
//! - When `hold == true`, local EOF does **not** propagate to the remote at
//!   all; the caller is expected to keep the remote socket open across
//!   multiple local connections (the `-P` mode).
//!
//! `remote` is borrowed mutably so that hold-session can keep the same
//! `TcpStream` alive across multiple accepts. We use `tokio::select!` rather
//! than `tokio::spawn` so we never move the borrowed halves into a `'static`
//! future.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::Result;

/// Run the relay until either side closes.
///
/// `remote` is borrowed mutably so that hold-session can keep the same
/// `TcpStream` alive across multiple accepts.
pub async fn relay<R, W>(
    local_r: R,
    mut local_w: W,
    remote: &mut TcpStream,
    hold: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut rr, mut rw) = remote.split();

    // local → remote. Half-closes `rw` when local EOFs (unless hold).
    let l2r = async {
        let mut lr = local_r;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                if !hold {
                    let _ = rw.shutdown().await;
                }
                return Ok::<(), std::io::Error>(());
            }
            rw.write_all(&buf[..n]).await?;
        }
    };

    // remote → local. Finishes on remote EOF, then shuts down the local writer.
    let r2l = async {
        tokio::io::copy(&mut rr, &mut local_w).await?;
        let _ = local_w.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    tokio::pin!(l2r);
    tokio::pin!(r2l);
    tokio::select! {
        l = &mut l2r => {
            if let Err(e) = &l { crate::error!("relay local→remote: {e}"); }
            // Drain remote→local before returning.
            if let Err(e) = r2l.await {
                crate::error!("relay remote→local (drain): {e}");
            }
        }
        r = &mut r2l => {
            if let Err(e) = &r { crate::error!("relay remote→local: {e}"); }
        }
    }
    Ok(())
}

/// Specialisation: relay stdin to a remote socket and back to stdout.
/// Used by the simple `sc host port` invocation.
pub async fn relay_stdio(mut remote: TcpStream) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    relay(stdin, stdout, &mut remote, false).await
}