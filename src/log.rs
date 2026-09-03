//! Initialise `tracing` once at startup.
//!
//! `tracing` and `tracing-subscriber` are the canonical log facade for
//! `sc`. Each `cfg.f_debug` step maps to a `tracing` level:
//!
//)
// 1 → DEBUG, 2 → TRACE; otherwise `RUST_LOG` (or "off") wins. After init
//! everything in the crate should use `tracing::*!` directly — there are
//! no wrapper macros on purpose so call sites stay readable.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialise the tracing-subscriber. Idempotent in the sense that calling
/// `try_init` only succeeds the first time, which is what we want: tests
/// that bypass `main` and call `init_tracing_for_tests` won't double-init.
pub fn init_tracing(f_debug: u8) {
    let default = match f_debug {
        0 => "off",
        1 => "debug",
        _ => "trace",
    };
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}