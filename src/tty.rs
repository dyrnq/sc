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
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

    const TTY_PATH: &str = "/dev/tty";

    pub fn read(prompt: &str) -> Result<String> {
        // Open /dev/tty.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TTY_PATH)
            .map_err(|e| Error::Config(format!("open {TTY_PATH}: {e}")))?;
        // Detach the file from its OwnedFd and use a BorrowedFd for termios.
        let raw = file.as_raw_fd();
        let owned = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let borrowed: BorrowedFd<'_> = unsafe { BorrowedFd::borrow_raw(raw) };
        let result = with_termios(borrowed, prompt);
        // Close the fd via the OwnedFd.
        drop(owned);
        result
    }

    fn with_termios(fd: BorrowedFd<'_>, prompt: &str) -> Result<String> {
        use nix::sys::termios::{self, SetArg, Termios};

        let orig: Termios =
            termios::tcgetattr(fd).map_err(|e| Error::Config(format!("tcgetattr: {e}")))?;
        let mut raw = orig.clone();
        raw.local_flags &= !(termios::LocalFlags::ECHO
            | termios::LocalFlags::ECHOE
            | termios::LocalFlags::ECHOK
            | termios::LocalFlags::ECHONL);

        termios::tcsetattr(fd, SetArg::TCSANOW, &raw)
            .map_err(|e| Error::Config(format!("tcsetattr: {e}")))?;

        // Write prompt via a std::fs::File wrapping the raw fd.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
        let _ = file.write_all(prompt.as_bytes());
        let _ = file.flush();

        // Read line byte-by-byte.
        let mut line = String::new();
        let mut byte = [0u8; 1];
        loop {
            match file.read(&mut byte) {
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

        // Restore termios. The File still owns the fd.
        let restore = termios::tcsetattr(fd, SetArg::TCSANOW, &orig);
        // Detach the File so it closes the fd on drop.
        std::mem::forget(file);
        // The BorrowedFd `fd` is a view; its Drop is a no-op anyway.
        let _ = fd;
        restore.map_err(|e| Error::Config(format!("tcsetattr restore: {e}")))?;
        Ok(line)
    }

    #[allow(dead_code)]
    fn _pin(_r: std::os::fd::RawFd) {}
}

// ---- Windows ----

#[cfg(windows)]
mod windows {
    use super::Result;
    use crate::error::Error;
    use std::io::{Read, Write};

    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
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
