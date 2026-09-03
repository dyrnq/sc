//! `sc` — ssh-connect: a SOCKS4/4a/5, HTTP CONNECT, and TELNET proxy relay.
//!
//! Drop-in replacement for the C `connect.c` tool used as OpenSSH `ProxyCommand`.
//! Currently Linux + macOS first; Windows support is being added incrementally.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod auth;
pub mod cli;
pub mod config;
pub mod direct_table;
pub mod error;
pub mod listen;
pub mod log;
pub mod parameters;
pub mod proxy;
pub mod relay;
pub mod resolve;
pub mod switch_ns;
pub mod tty;

pub use error::{Error, Result};
