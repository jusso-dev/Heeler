//! Typed errors for the core protocol crate.
//!
//! Library code in this crate never panics on untrusted input; every fallible
//! operation returns one of the error types below.

use crate::packet::Mode;

/// Errors produced while parsing an inbound NTP packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The datagram is shorter than the 48-byte base NTP packet.
    #[error("packet too short: {actual} bytes, need at least 48")]
    TooShort {
        /// Number of bytes actually received.
        actual: usize,
    },
}

/// Errors produced while converting between time representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimestampError {
    /// The instant is before the NTP epoch (1900-01-01) and cannot be
    /// represented as a non-negative NTP timestamp.
    #[error("instant predates the NTP epoch (1900-01-01T00:00:00Z)")]
    BeforeNtpEpoch,
    /// The instant cannot be represented by the platform `SystemTime`.
    #[error("instant is outside the range representable by SystemTime")]
    OutOfSystemTimeRange,
}

/// Errors produced by a clock source.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    /// The operating system reported an error reading the clock.
    #[error("system clock read failed: {0}")]
    SystemClock(String),
    /// The clock reading could not be converted to NTP representation.
    #[error("clock reading not representable: {0}")]
    Unrepresentable(#[from] TimestampError),
    /// A scripted mock clock ran out of readings.
    #[error("mock clock has no scripted reading available")]
    MockExhausted,
}

/// Errors produced while validating protocol-level configuration values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// Stratum 0 is a Kiss-o'-Death marker, not a valid server stratum.
    #[error("stratum 0 is reserved for Kiss-o'-Death packets and cannot be configured")]
    StratumZero,
    /// Strata above 15 are not valid synchronised server strata.
    #[error("stratum {0} is invalid: synchronised servers use 1-15")]
    StratumTooHigh(u8),
    /// The reference identifier string is not encodable as four bytes.
    #[error("reference identifier {0:?} must be 1-4 printable ASCII characters")]
    InvalidReferenceId(String),
    /// A stratum-1 configuration requires an explicit reference identifier.
    #[error("stratum 1 requires an explicit reference_id naming the reference source (e.g. \"GPS\", \"PPS\", \"LOCL\")")]
    StratumOneNeedsReferenceId,
    /// The leap indicator value is out of range.
    #[error("leap indicator {0} is invalid: must be 0-3")]
    InvalidLeapIndicator(u8),
    /// A fixed-point field is out of the representable 16.16 range.
    #[error("value {0} ms is outside the representable NTP short format range")]
    FixedPointOutOfRange(i64),
}

/// The reason an otherwise well-formed packet was not accepted as a client
/// request. Used by the validation layer; the server decides whether each
/// variant is silently dropped, counted, or answered with a Kiss-o'-Death.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRejection {
    /// Trailing bytes after the 48-byte base packet and policy forbids them.
    TrailingData {
        /// Number of trailing bytes observed.
        trailing: usize,
    },
    /// The version number is not served by this instance.
    UnsupportedVersion(u8),
    /// The packet mode is not a client request.
    UnsupportedMode(Mode),
    /// Policy requires a non-zero client transmit timestamp.
    ZeroTransmitTimestamp,
}

impl std::fmt::Display for RequestRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrailingData { trailing } => {
                write!(f, "unexpected trailing data ({trailing} bytes)")
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported NTP version {v}"),
            Self::UnsupportedMode(m) => write!(f, "unsupported mode {m}"),
            Self::ZeroTransmitTimestamp => write!(f, "zero client transmit timestamp"),
        }
    }
}
