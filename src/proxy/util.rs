//! Shared line-reader used by the HTTP and TELNET proxy handshakes.
//!
//! Both protocols arrive as byte streams of CRLF-terminated ASCII lines
//! (status / response headers for HTTP, banner lines for TELNET), so the
//! "read one line, strip `\r`, return when we see `\n`" loop is identical.
//! This module is the single home for that loop — protocol modules call
//! [`read_crlf_line`] and stay focused on their own state machines.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::Result;

/// Read one CRLF-terminated line into `buf`.
///
/// `buf` is cleared first. `\r` is dropped; the line ends at the first `\n`
/// (which is also dropped). Non-ASCII bytes are pushed as `char` (lossy).
///
/// Returns:
///
/// - `Ok(true)` on EOF (peer closed). `buf` may be empty (no partial line)
///   or hold the trailing partial line (peer closed mid-CR-strip). Callers
///   can distinguish via `buf.is_empty()` if they care.
/// - `Ok(false)` on a normal `\n`-terminated line.
///
/// `R` is generic so tests can drive it against `tokio::io::Cursor` /
/// `tokio::io::duplex` without a real TCP listener.
pub async fn read_crlf_line<R: AsyncRead + Unpin>(r: &mut R, buf: &mut String) -> Result<bool> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            return Ok(true);
        }
        if byte[0] == b'\n' {
            return Ok(false);
        }
        if byte[0] != b'\r' {
            buf.push(byte[0] as char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Two-line input → two reads, `\r` stripped, `\n` not included.
    #[tokio::test]
    async fn reads_two_lines_strips_cr() {
        let mut c = Cursor::new(b"hello\r\nworld\r\n".to_vec());
        let mut s = String::new();

        let eof = read_crlf_line(&mut c, &mut s).await.unwrap();
        assert!(!eof);
        assert_eq!(s, "hello");

        let eof = read_crlf_line(&mut c, &mut s).await.unwrap();
        assert!(!eof);
        assert_eq!(s, "world");
    }

    /// EOF after a partial line: caller sees `eof=true` and the trailing
    /// bytes in `buf`.
    #[tokio::test]
    async fn eof_with_partial_line_reports_eof() {
        let mut c = Cursor::new(b"dangling".to_vec());
        let mut s = String::new();

        let eof = read_crlf_line(&mut c, &mut s).await.unwrap();
        assert!(eof);
        assert_eq!(s, "dangling");
    }

    /// Clean EOF with nothing buffered: `eof=true`, `buf` empty. This is
    /// the signal HTTP / TELNET parsers use to break out of header / banner
    /// loops.
    #[tokio::test]
    async fn clean_eof_returns_empty_buf() {
        let mut c = Cursor::new(Vec::<u8>::new());
        let mut s = String::new();

        let eof = read_crlf_line(&mut c, &mut s).await.unwrap();
        assert!(eof);
        assert!(s.is_empty());
    }

    /// Bare `\n` (no preceding `\r`) is a valid line terminator — the
    /// wire format is "CRLF" but a stray LF is universally accepted.
    #[tokio::test]
    async fn bare_lf_terminates() {
        let mut c = Cursor::new(b"only-lf\n".to_vec());
        let mut s = String::new();

        let eof = read_crlf_line(&mut c, &mut s).await.unwrap();
        assert!(!eof);
        assert_eq!(s, "only-lf");
    }
}
