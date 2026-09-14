//! Terminal no-echo password input.
//!
//! Unix: opens `/dev/tty`, disables `ECHO|ECHOE|ECHOK|ECHONL` via `tcsetattr`,
//! restores on exit.
//!
//! Windows: opens the console input handle, clears `ENABLE_ECHO_INPUT` via
//! `SetConsoleMode`, restores on exit.
//!
//! Mirrors `connect.c::tty_readpass` (lines 1253-1290 / 1294-1320).

use crate::error::Result;

/// Read a password from the controlling terminal. Echo is disabled during
/// input and restored on exit.
pub fn tty_readpass(prompt: &str) -> Result<String> {
    #[cfg(unix)]
    return unix::read(prompt);
    #[cfg(windows)]
    return windows::read(prompt);
    #[cfg(not(any(unix, windows)))]
    {
        let _ = prompt;
        Err(Error::Todo("tty_readpass on this platform"))
    }
}

// ---- Unix ----

#[cfg(unix)]
mod unix {
    use super::Result;
    use crate::error::Error;
    use nix::sys::termios::{self, LocalFlags, SetArg};
    use std::fs::File;
    use std::io::{Read, Write};

    const TTY_PATH: &str = "/dev/tty";

    pub fn read(prompt: &str) -> Result<String> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TTY_PATH)
            .map_err(|e| Error::Config(format!("open {TTY_PATH}: {e}")))?;
        with_termios(&mut file, prompt)
    }

    /// Disable echo, prompt, read one line, restore echo. One `&mut File`
    /// owns the fd for its entire lifetime — matching connect.c's single-fd
    /// pattern (no `OwnedFd` / `BorrowedFd` aliasing).
    fn with_termios(file: &mut File, prompt: &str) -> Result<String> {
        let orig =
            termios::tcgetattr(&*file).map_err(|e| Error::Config(format!("tcgetattr: {e}")))?;
        let mut raw = orig.clone();
        raw.local_flags &=
            !(LocalFlags::ECHO | LocalFlags::ECHOE | LocalFlags::ECHOK | LocalFlags::ECHONL);

        termios::tcsetattr(&*file, SetArg::TCSANOW, &raw)
            .map_err(|e| Error::Config(format!("tcsetattr: {e}")))?;

        let _ = file.write_all(prompt.as_bytes());
        let _ = file.flush();

        let mut line = String::new();
        let mut byte = [0u8; 1];
        loop {
            match file.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    if byte[0] != b'\r' {
                        line.push(byte[0] as char);
                    }
                }
            }
        }

        termios::tcsetattr(&*file, SetArg::TCSANOW, &orig)
            .map_err(|e| Error::Config(format!("tcsetattr restore: {e}")))?;
        Ok(line)
    }
}

// ---- Windows ----

#[cfg(windows)]
mod windows {
    use super::Result;
    use crate::error::Error;
    use std::io::{Read, Write};

    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };

    pub fn read(prompt: &str) -> Result<String> {
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            if h.is_null() {
                return Err(Error::Config("no console input handle".into()));
            }
            let mut orig_mode: u32 = 0;
            if GetConsoleMode(h, &mut orig_mode) == 0 {
                return Err(Error::Config("GetConsoleMode failed".into()));
            }
            let new_mode = orig_mode & !ENABLE_ECHO_INPUT;
            if SetConsoleMode(h, new_mode) == 0 {
                return Err(Error::Config("SetConsoleMode failed".into()));
            }

            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(prompt.as_bytes());
            let _ = stderr.flush();

            let mut line = String::new();
            let stdin = std::io::stdin();
            let mut handle = stdin.lock();
            let mut byte = [0u8; 1];
            loop {
                match handle.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => {
                        if byte[0] == b'\n' {
                            break;
                        }
                        if byte[0] != b'\r' {
                            line.push(byte[0] as char);
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = SetConsoleMode(h, orig_mode);
            Ok(line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When `/dev/tty` cannot be opened (no controlling terminal, or run
    /// in a container without one), `tty_readpass` must surface a
    /// Config-typed error rather than panicking. This pins the
    /// open-failure path — the only path we can exercise without a real
    /// TTY attached to the test harness.
    #[cfg(unix)]
    #[test]
    fn tty_readpass_returns_err_when_dev_tty_unavailable() {
        // Best-effort: if `/dev/tty` is actually openable (e.g. local dev
        // machine), we cannot reliably exercise the failure path without
        // risking a real read. Skip the test in that case.
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
        {
            eprintln!("skipping: /dev/tty is openable on this host");
            return;
        }
        let result = tty_readpass("prompt: ");
        assert!(
            matches!(result, Err(crate::error::Error::Config(_))),
            "expected Config error from open failure, got {result:?}"
        );
    }
}
