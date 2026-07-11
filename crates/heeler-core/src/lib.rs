//! Core protocol primitives for the Heeler NTP server.
//!
//! This crate implements the NTPv4 wire format (RFC 5905 subset) from first
//! principles:
//!
//! * [`packet`] — parsing and encoding of the 48-byte base NTP packet with
//!   explicit big-endian byte handling and no unsafe casting;
//! * [`timestamp`] — the 64-bit NTP timestamp format, the 1900/1970 epoch
//!   conversion, and era unfolding around the 2036 rollover;
//! * [`clock`] — the [`clock::ClockSource`] abstraction with a system-clock
//!   implementation and a deterministic mock for tests;
//! * [`validation`] — request-acceptance policy for inbound packets;
//! * [`response`] — construction of protocol-correct server-mode responses
//!   and Kiss-o'-Death packets;
//! * [`error`] — typed errors shared by the modules above.
//!
//! The crate is intentionally free of async runtimes and networking so the
//! protocol logic can be tested and fuzzed in isolation.

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unreachable_pub,
    unused_qualifications,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
// Tests may unwrap/panic: a failed assertion is the point.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod clock;
pub mod error;
pub mod packet;
pub mod response;
pub mod timestamp;
pub mod validation;

pub use clock::{ClockPrecision, ClockReading, ClockSource, ClockStatus};
pub use error::{ClockError, ConfigError, ParseError, RequestRejection, TimestampError};
pub use packet::{
    KissCode, LeapIndicator, Mode, NtpPacket, NtpShortSigned, NtpShortUnsigned, NtpVersion,
    ParsedPacket, ReferenceId, Stratum, PACKET_SIZE,
};
pub use response::ServerIdentity;
pub use timestamp::{NtpInstant, NtpTimestamp, UNIX_TO_NTP_OFFSET_SECONDS};
pub use validation::ValidationPolicy;
