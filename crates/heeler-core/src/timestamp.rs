//! NTP timestamp representation and epoch/era arithmetic.
//!
//! # Wire format
//!
//! An NTP timestamp is a 64-bit unsigned fixed-point value: the upper 32 bits
//! count whole seconds since 1900-01-01T00:00:00Z (the *NTP epoch*) and the
//! lower 32 bits count fractional seconds in units of 2⁻³² s (~233 ps).
//!
//! # Eras
//!
//! The 32-bit seconds field wraps every 2³² s ≈ 136 years; the first wrap
//! ("era 1") begins on 2036-02-07. A wire-format timestamp is therefore
//! ambiguous without context. Internally Heeler keeps time as an
//! [`NtpInstant`]: a signed 128-bit count of nanoseconds since the NTP epoch,
//! which is unambiguous for any realistic time. Encoding emits the low 32
//! bits of the absolute second count; decoding resolves the era against a
//! pivot instant via [`NtpTimestamp::unfold`].
//!
//! # Rounding
//!
//! Fraction conversions truncate toward zero (floor for the non-negative
//! values involved):
//!
//! * nanoseconds → fraction: `floor(nanos × 2³² / 10⁹)`
//! * fraction → nanoseconds: `floor(fraction × 10⁹ / 2³²)`
//!
//! Both are computed with 128-bit intermediates so no precision beyond the
//! inherent quantisation is lost. The maximum round-trip error is < 1 ns.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::TimestampError;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
pub const UNIX_TO_NTP_OFFSET_SECONDS: u64 = 2_208_988_800;

const NANOS_PER_SECOND: i128 = 1_000_000_000;
const TWO_POW_32: i128 = 1 << 32;

/// A 64-bit NTP wire-format timestamp: 32-bit seconds, 32-bit fraction.
///
/// The seconds field is the low 32 bits of the absolute second count since
/// 1900 and requires era context to interpret; see the module docs and
/// [`NtpTimestamp::unfold`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtpTimestamp {
    seconds: u32,
    fraction: u32,
}

impl NtpTimestamp {
    /// The all-zero timestamp, used by clients that do not fill in a field
    /// and conventionally meaning "unknown".
    pub const ZERO: Self = Self {
        seconds: 0,
        fraction: 0,
    };

    /// Builds a timestamp from raw wire-format seconds and fraction.
    #[must_use]
    pub const fn new(seconds: u32, fraction: u32) -> Self {
        Self { seconds, fraction }
    }

    /// Wire-format seconds (low 32 bits of the absolute second count).
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.seconds
    }

    /// Wire-format fraction in units of 2⁻³² seconds.
    #[must_use]
    pub const fn fraction(self) -> u32 {
        self.fraction
    }

    /// Whether both fields are zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.seconds == 0 && self.fraction == 0
    }

    /// Decodes from the 8 network-order bytes of a packet field.
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        let seconds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fraction = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self { seconds, fraction }
    }

    /// Encodes to the 8 network-order bytes of a packet field.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.seconds.to_be_bytes());
        out[4..].copy_from_slice(&self.fraction.to_be_bytes());
        out
    }

    /// The raw 64-bit fixed-point value (seconds in the high half).
    #[must_use]
    pub const fn to_bits(self) -> u64 {
        ((self.seconds as u64) << 32) | self.fraction as u64
    }

    /// Builds a timestamp from the raw 64-bit fixed-point value.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self {
            seconds: (bits >> 32) as u32,
            fraction: bits as u32,
        }
    }

    /// Converts a sub-second nanosecond count (must be < 10⁹) into the
    /// 32-bit fraction, truncating toward zero.
    #[must_use]
    pub fn fraction_from_nanos(nanos: u32) -> u32 {
        // Guard the contract instead of silently overflowing: values >= 1 s
        // are folded into the sub-second range.
        let nanos = u128::from(nanos % 1_000_000_000);
        // nanos * 2^32 / 10^9 < 2^32, so the cast is lossless.
        ((nanos << 32) / 1_000_000_000) as u32
    }

    /// Converts the 32-bit fraction into nanoseconds, truncating toward zero.
    /// The result is always < 10⁹.
    #[must_use]
    pub fn fraction_to_nanos(fraction: u32) -> u32 {
        // fraction * 10^9 / 2^32 < 10^9, so the cast is lossless.
        ((u128::from(fraction) * 1_000_000_000) >> 32) as u32
    }

    /// Resolves this wire-format timestamp to an absolute instant by picking
    /// the NTP era that places it closest to `pivot` (always within ±68
    /// years). A pivot near the current time correctly decodes timestamps
    /// on both sides of the 2036 rollover.
    #[must_use]
    pub fn unfold(self, pivot: NtpInstant) -> NtpInstant {
        let pivot_seconds = pivot.nanos.div_euclid(NANOS_PER_SECOND);
        let wire_seconds = i128::from(self.seconds);
        // Era index that minimises |wire + era*2^32 - pivot|.
        let era = (pivot_seconds - wire_seconds + TWO_POW_32 / 2).div_euclid(TWO_POW_32);
        let absolute_seconds = wire_seconds + era * TWO_POW_32;
        NtpInstant {
            nanos: absolute_seconds * NANOS_PER_SECOND
                + i128::from(Self::fraction_to_nanos(self.fraction)),
        }
    }
}

impl std::fmt::Display for NtpTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:010}", self.seconds, self.fraction)
    }
}

/// An absolute instant: signed nanoseconds since the NTP epoch (1900-01-01).
///
/// This is the internal, era-unambiguous time representation. It covers all
/// of civil time from far before 1900 to far after the 2036 rollover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NtpInstant {
    nanos: i128,
}

impl NtpInstant {
    /// The NTP epoch itself, 1900-01-01T00:00:00Z.
    pub const EPOCH: Self = Self { nanos: 0 };

    /// Builds an instant from nanoseconds since the NTP epoch.
    #[must_use]
    pub const fn from_ntp_nanos(nanos: i128) -> Self {
        Self { nanos }
    }

    /// Nanoseconds since the NTP epoch (may be negative for pre-1900 times).
    #[must_use]
    pub const fn as_ntp_nanos(self) -> i128 {
        self.nanos
    }

    /// Builds an instant from nanoseconds since the Unix epoch.
    #[must_use]
    pub const fn from_unix_nanos(unix_nanos: i128) -> Self {
        Self {
            nanos: unix_nanos + UNIX_TO_NTP_OFFSET_SECONDS as i128 * NANOS_PER_SECOND,
        }
    }

    /// Nanoseconds since the Unix epoch (negative for pre-1970 times).
    #[must_use]
    pub const fn as_unix_nanos(self) -> i128 {
        self.nanos - UNIX_TO_NTP_OFFSET_SECONDS as i128 * NANOS_PER_SECOND
    }

    /// Converts a platform `SystemTime`, handling times before the Unix
    /// epoch without panicking.
    #[must_use]
    pub fn from_system_time(time: SystemTime) -> Self {
        let unix_nanos = match time.duration_since(UNIX_EPOCH) {
            Ok(after) => after.as_nanos() as i128,
            // Pre-1970: the error carries the positive distance to the epoch.
            Err(before) => -(before.duration().as_nanos() as i128),
        };
        Self::from_unix_nanos(unix_nanos)
    }

    /// Converts back to a `SystemTime`, failing (not panicking) if the
    /// instant is outside the platform-representable range.
    pub fn to_system_time(self) -> Result<SystemTime, TimestampError> {
        let unix_nanos = self.as_unix_nanos();
        let magnitude = unix_nanos.unsigned_abs();
        let seconds = u64::try_from(magnitude / NANOS_PER_SECOND as u128)
            .map_err(|_| TimestampError::OutOfSystemTimeRange)?;
        let sub_nanos = (magnitude % NANOS_PER_SECOND as u128) as u32;
        let duration = Duration::new(seconds, sub_nanos);
        let result = if unix_nanos >= 0 {
            UNIX_EPOCH.checked_add(duration)
        } else {
            UNIX_EPOCH.checked_sub(duration)
        };
        result.ok_or(TimestampError::OutOfSystemTimeRange)
    }

    /// Encodes as a wire-format timestamp: the low 32 bits of the absolute
    /// second count plus the 32-bit fraction. Fails for pre-1900 instants,
    /// which have no non-negative NTP representation.
    pub fn to_timestamp(self) -> Result<NtpTimestamp, TimestampError> {
        if self.nanos < 0 {
            return Err(TimestampError::BeforeNtpEpoch);
        }
        let seconds = self.nanos.div_euclid(NANOS_PER_SECOND);
        let sub_nanos = self.nanos.rem_euclid(NANOS_PER_SECOND) as u32;
        Ok(NtpTimestamp {
            // Era truncation is deliberate: the wire carries only the low
            // 32 bits and the receiver unfolds them against a pivot.
            seconds: (seconds & 0xFFFF_FFFF) as u32,
            fraction: NtpTimestamp::fraction_from_nanos(sub_nanos),
        })
    }

    /// Adds a signed number of nanoseconds.
    #[must_use]
    pub const fn add_nanos(self, delta: i128) -> Self {
        Self {
            nanos: self.nanos + delta,
        }
    }

    /// Signed difference `self - other` in nanoseconds.
    #[must_use]
    pub const fn nanos_since(self, other: Self) -> i128 {
        self.nanos - other.nanos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-01-01T00:00:00Z in Unix seconds.
    const UNIX_2026: i128 = 1_767_225_600;
    /// The 2036 era boundary: NTP second 2^32 == Unix second 2_085_978_496.
    const UNIX_ERA_BOUNDARY: i128 = TWO_POW_32 - UNIX_TO_NTP_OFFSET_SECONDS as i128;

    fn instant_at_unix_seconds(seconds: i128) -> NtpInstant {
        NtpInstant::from_unix_nanos(seconds * NANOS_PER_SECOND)
    }

    #[test]
    fn unix_epoch_encodes_to_offset_seconds() {
        let ts = instant_at_unix_seconds(0).to_timestamp().unwrap();
        assert_eq!(u64::from(ts.seconds()), UNIX_TO_NTP_OFFSET_SECONDS);
        assert_eq!(ts.fraction(), 0);
    }

    #[test]
    fn ntp_epoch_is_zero() {
        let ts = NtpInstant::EPOCH.to_timestamp().unwrap();
        assert!(ts.is_zero());
    }

    #[test]
    fn pre_1900_is_rejected() {
        let pre = NtpInstant::from_ntp_nanos(-1);
        assert_eq!(pre.to_timestamp(), Err(TimestampError::BeforeNtpEpoch));
    }

    #[test]
    fn pre_1970_system_time_round_trips() {
        let t = UNIX_EPOCH - Duration::from_secs(86_400);
        let instant = NtpInstant::from_system_time(t);
        assert_eq!(instant.as_unix_nanos(), -86_400 * NANOS_PER_SECOND);
        assert_eq!(instant.to_system_time().unwrap(), t);
    }

    #[test]
    fn fraction_conversion_known_values() {
        // 0.5 s == 0x8000_0000
        assert_eq!(NtpTimestamp::fraction_from_nanos(500_000_000), 0x8000_0000);
        assert_eq!(NtpTimestamp::fraction_to_nanos(0x8000_0000), 500_000_000);
        // 0.25 s == 0x4000_0000
        assert_eq!(NtpTimestamp::fraction_from_nanos(250_000_000), 0x4000_0000);
        // Maximum fraction is just below one second.
        assert_eq!(NtpTimestamp::fraction_to_nanos(u32::MAX), 999_999_999);
        assert_eq!(NtpTimestamp::fraction_from_nanos(0), 0);
    }

    #[test]
    fn fraction_round_trip_error_below_one_nanosecond() {
        for nanos in [0u32, 1, 2, 999, 123_456_789, 500_000_000, 999_999_999] {
            let back = NtpTimestamp::fraction_to_nanos(NtpTimestamp::fraction_from_nanos(nanos));
            assert!(
                back <= nanos && nanos - back <= 1,
                "nanos={nanos} back={back}"
            );
        }
    }

    #[test]
    fn second_carry_boundary() {
        // 999_999_999 ns must stay below the next second.
        let instant = instant_at_unix_seconds(UNIX_2026).add_nanos(999_999_999);
        let ts = instant.to_timestamp().unwrap();
        let base = instant_at_unix_seconds(UNIX_2026).to_timestamp().unwrap();
        assert_eq!(ts.seconds(), base.seconds());
        assert!(ts.fraction() > 0xFFFF_FFF0);
    }

    #[test]
    fn unfold_current_era() {
        let pivot = instant_at_unix_seconds(UNIX_2026);
        let ts = pivot.to_timestamp().unwrap();
        assert_eq!(ts.unfold(pivot), pivot);
    }

    #[test]
    fn unfold_just_before_2036_rollover() {
        let pivot = instant_at_unix_seconds(UNIX_ERA_BOUNDARY);
        let before = instant_at_unix_seconds(UNIX_ERA_BOUNDARY - 1);
        let ts = before.to_timestamp().unwrap();
        assert_eq!(ts.seconds(), u32::MAX);
        assert_eq!(ts.unfold(pivot), before);
    }

    #[test]
    fn unfold_just_after_2036_rollover() {
        // A pivot still in era 0 must correctly place an era-1 timestamp.
        let pivot = instant_at_unix_seconds(UNIX_ERA_BOUNDARY - 3600);
        let after = instant_at_unix_seconds(UNIX_ERA_BOUNDARY + 1);
        let ts = after.to_timestamp().unwrap();
        assert_eq!(ts.seconds(), 1);
        assert_eq!(ts.unfold(pivot), after);
    }

    #[test]
    fn unfold_era_boundary_exact() {
        let pivot = instant_at_unix_seconds(UNIX_ERA_BOUNDARY + 10);
        let boundary = instant_at_unix_seconds(UNIX_ERA_BOUNDARY);
        let ts = boundary.to_timestamp().unwrap();
        assert_eq!(ts.seconds(), 0);
        assert_eq!(ts.unfold(pivot), boundary);
    }

    #[test]
    fn unfold_near_unix_epoch() {
        let pivot = instant_at_unix_seconds(0);
        let near = instant_at_unix_seconds(60);
        assert_eq!(near.to_timestamp().unwrap().unfold(pivot), near);
    }

    #[test]
    fn zero_timestamp_unfolds_to_nearest_era_boundary() {
        // A zero timestamp against a 2026 pivot resolves to the era-1
        // boundary (2036, ~10 years away), not 1900 (~126 years away):
        // unfold always picks the era placing the instant closest to the
        // pivot, guaranteeing a result within ±68 years.
        let pivot = instant_at_unix_seconds(UNIX_2026);
        assert_eq!(
            NtpTimestamp::ZERO.unfold(pivot),
            instant_at_unix_seconds(UNIX_ERA_BOUNDARY)
        );
        // Against an early pivot (1900-1968) it resolves to era 0. Note a
        // 1970 pivot already resolves to era 1: 2036 is 66 years away,
        // 1900 is 70.
        let early_pivot = NtpInstant::EPOCH;
        assert_eq!(NtpTimestamp::ZERO.unfold(early_pivot), NtpInstant::EPOCH);
    }

    #[test]
    fn wire_bytes_round_trip() {
        let ts = NtpTimestamp::new(0xDEAD_BEEF, 0x0123_4567);
        assert_eq!(NtpTimestamp::from_be_bytes(ts.to_be_bytes()), ts);
        assert_eq!(
            ts.to_be_bytes(),
            [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67]
        );
        assert_eq!(NtpTimestamp::from_bits(ts.to_bits()), ts);
    }
}
