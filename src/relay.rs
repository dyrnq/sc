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
//! Implementation: each direction runs as its own `tokio::spawn`ed task and
//! signals completion via a `oneshot`. The outer function awaits both, but
//! once either finishes, we keep the other running (matching connect.c).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::error::Result;

/// Run the relay until either side closes.
pub async fn relay<R, W>(local_r: R, local_w: W, remote: TcpStream, hold: bool) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (rr, rw) = remote.into_split();

    // local → remote. Half-closes `rw` when local EOFs (unless hold).
    let l2r = async move {
        let mut lr = local_r;
        let mut rw = rw;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match lr.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => return Err(e),
            };
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
    let r2l = async move {
        let mut rr = rr;
        let mut lw = local_w;
        tokio::io::copy(&mut rr, &mut lw).await?;
        let _ = lw.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    let (l_tx, l_rx) = oneshot::channel::<std::io::Result<()>>();
    let (r_tx, r_rx) = oneshot::channel::<std::io::Result<()>>();
    tokio::spawn(async move {
        let _ = l_tx.send(l2r.await);
    });
    tokio::spawn(async move {
        let _ = r_tx.send(r2l.await);
    });

    // Wait for whichever side finishes first. If it was local-to-remote, we
    // keep waiting for remote-to-local to finish its drain. If it was the
    // remote-to-local side, we close the local writer (already done inside
    // r2l) and wait for the local-to-remote task to also finish.
    let l_result = l_rx.await.unwrap_or_else(|_| Err(std::io::Error::other("local task dropped")));
    let r_result = r_rx.await.unwrap_or_else(|_| Err(std::io::Error::other("remote task dropped")));

    if let Err(e) = &l_result {
        crate::error!("relay local→remote: {e}");
    }
    if let Err(e) = &r_result {
        crate::error!("relay remote→local: {e}");
    }
    Ok(())
}

/// Specialisation: relay stdin to a remote socket and back to stdout.
/// Used by the simple `sc host port` invocation.
pub async fn relay_stdio(remote: TcpStream) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    relay(stdin, stdout, remote, false).await
}
