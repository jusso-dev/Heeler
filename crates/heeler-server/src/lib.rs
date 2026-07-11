//! Heeler server runtime: configuration, sockets, security controls,
//! observability, and the CLI building blocks.
//!
//! The wire protocol itself lives in `heeler-core`; this crate wires it to
//! the operating system. Exposed as a library so integration tests can run
//! a real server on an ephemeral port.

#![deny(unsafe_code)]
#![warn(
    rust_2018_idioms,
    unused_qualifications,
    clippy::unwrap_used,
    clippy::expect_used
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod access;
pub mod bench;
pub mod client;
pub mod config;
pub mod inspect;
pub mod metrics;
pub mod rate_limit;
pub mod server;
pub mod shutdown;

/// Privilege drop uses libc identity syscalls; the `unsafe` is isolated
/// here (see the module docs for the invariants).
#[cfg(unix)]
#[allow(unsafe_code)]
pub mod privilege;
