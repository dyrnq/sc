//! Logging macros that mirror `connect.c`'s `debug` / `error` / `fatal`.
//!
//! - `debug!` prints to stderr only when `Config::debug` is set.
//! - `error!` always prints to stderr but does not exit.
//! - `fatal!` prints to stderr and terminates the process with exit code 1.

/// Print a debug message to stderr (only when `Config::debug` is true).
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::config::Config::global_debug() {
            eprintln!("[debug] {}", format_args!($($arg)*));
        }
    };
}

/// Print an error message to stderr and continue.
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        eprintln!("[error] {}", format_args!($($arg)*));
    };
}

/// Print an error message to stderr and exit with status 1.
#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {{
        eprintln!("[fatal] {}", format_args!($($arg)*));
        std::process::exit(1);
    }};
}

/// Initialise `tracing`-based logging when `SC_LOG` is set.
pub fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let _ = fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off")))
        .with_writer(std::io::stderr)
        .try_init();
}
