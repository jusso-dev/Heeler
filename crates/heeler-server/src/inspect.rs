//! `heeler inspect-packet`: decode a hex-encoded NTP packet for humans.

use heeler_core::packet::{NtpPacket, ParsedPacket};
use heeler_core::timestamp::{NtpInstant, NtpTimestamp};

/// Errors from packet inspection.
#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    /// The input was not valid hexadecimal.
    #[error("invalid hex at position {0}")]
    InvalidHex(usize),
    /// The hex had an odd number of digits.
    #[error("odd number of hex digits")]
    OddLength,
    /// The bytes did not form a base NTP packet.
    #[error(transparent)]
    Parse(#[from] heeler_core::error::ParseError),
}

/// Decodes a hex string (whitespace and an optional `0x` prefix are
/// tolerated) into bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, InspectError> {
    let cleaned: String = input
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err(InspectError::OddLength);
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let digits: Vec<char> = cleaned.chars().collect();
    for (i, pair) in digits.chunks(2).enumerate() {
        let hi = pair[0].to_digit(16).ok_or(InspectError::InvalidHex(i * 2))?;
        let lo = pair[1]
            .to_digit(16)
            .ok_or(InspectError::InvalidHex(i * 2 + 1))?;
        bytes.push((hi * 16 + lo) as u8);
    }
    Ok(bytes)
}

/// Parses hex input and renders every field.
pub fn inspect(input: &str, pivot: NtpInstant) -> Result<String, InspectError> {
    let bytes = decode_hex(input)?;
    let parsed = NtpPacket::parse(&bytes)?;
    Ok(render(&parsed, pivot))
}

fn render(parsed: &ParsedPacket, pivot: NtpInstant) -> String {
    use std::fmt::Write as _;
    let p = &parsed.packet;
    let mut out = String::new();
    let _ = writeln!(out, "leap indicator    {}", p.leap);
    let _ = writeln!(out, "version           {}", p.version);
    let _ = writeln!(out, "mode              {}", p.mode);
    let _ = writeln!(out, "stratum           {}", p.stratum);
    let _ = writeln!(out, "poll              {} (2^{} s)", p.poll, p.poll);
    let _ = writeln!(out, "precision         {} (2^{} s)", p.precision, p.precision);
    let _ = writeln!(
        out,
        "root delay        0x{:08X} ({:.6} s)",
        p.root_delay.to_bits() as u32,
        p.root_delay.to_seconds_f64()
    );
    let _ = writeln!(
        out,
        "root dispersion   0x{:08X} ({:.6} s)",
        p.root_dispersion.to_bits(),
        p.root_dispersion.to_seconds_f64()
    );
    let _ = writeln!(out, "reference id      {}", p.reference_id);
    let _ = writeln!(
        out,
        "reference ts      {}",
        render_timestamp(p.reference_timestamp, pivot)
    );
    let _ = writeln!(
        out,
        "origin ts (T1)    {}",
        render_timestamp(p.origin_timestamp, pivot)
    );
    let _ = writeln!(
        out,
        "receive ts (T2)   {}",
        render_timestamp(p.receive_timestamp, pivot)
    );
    let _ = writeln!(
        out,
        "transmit ts (T3)  {}",
        render_timestamp(p.transmit_timestamp, pivot)
    );
    if parsed.trailing_bytes > 0 {
        let _ = writeln!(
            out,
            "trailing data     {} uninterpreted byte(s) after the base packet",
            parsed.trailing_bytes
        );
    }
    let _ = write!(
        out,
        "note: era resolved against the current time; wire timestamps carry \
         only the low 32 bits of the second count"
    );
    out
}

fn render_timestamp(ts: NtpTimestamp, pivot: NtpInstant) -> String {
    if ts.is_zero() {
        return "0x0000000000000000 (zero / unknown)".to_owned();
    }
    format!(
        "0x{:016X} ({})",
        ts.to_bits(),
        format_instant(ts.unfold(pivot))
    )
}

/// Formats an instant as an RFC 3339-style UTC string with nanoseconds.
///
/// Uses the standard civil-from-days algorithm; no timezone database is
/// consulted (NTP time is UTC by definition).
#[must_use]
pub fn format_instant(instant: NtpInstant) -> String {
    let unix_nanos = instant.as_unix_nanos();
    let seconds = unix_nanos.div_euclid(1_000_000_000);
    let nanos = unix_nanos.rem_euclid(1_000_000_000) as u32;

    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days as i64);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z"
    )
}

/// Days-since-Unix-epoch to (year, month, day) in the proleptic Gregorian
/// calendar (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month index, March-based
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decoding() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xFF, 0x10]);
        assert_eq!(decode_hex("0xDEAD BEEF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(decode_hex("  23 00 \n 06 ec ").unwrap(), vec![0x23, 0, 6, 0xEC]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn civil_date_known_values() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // 2024-01-01
        assert_eq!(civil_from_days(-25_567), (1900, 1, 1)); // NTP epoch
        assert_eq!(civil_from_days(24_106), (2036, 1, 1));
    }

    #[test]
    fn format_instant_epoch() {
        let epoch = NtpInstant::from_unix_nanos(0);
        assert_eq!(format_instant(epoch), "1970-01-01T00:00:00.000000000Z");
        let later = NtpInstant::from_unix_nanos(1_700_000_000_123_456_789);
        assert_eq!(format_instant(later), "2023-11-14T22:13:20.123456789Z");
    }

    #[test]
    fn inspect_golden_request() {
        let hex = "230006ec00000000000000000000000000000000000000000000000000000000\
                   0000000000000000e3b0f2ac80000000";
        let now = NtpInstant::from_unix_nanos(1_600_000_000_000_000_000);
        let text = inspect(hex, now).unwrap();
        assert!(text.contains("mode              3 (client)"));
        assert!(text.contains("version           4"));
        assert!(text.contains("poll              6"));
        assert!(text.contains("precision         -20"));
        assert!(text.contains("transmit ts (T3)  0xE3B0F2AC80000000"));
    }

    #[test]
    fn inspect_reports_trailing() {
        let hex = format!("23{}", "00".repeat(51));
        let now = NtpInstant::from_unix_nanos(1_600_000_000_000_000_000);
        let text = inspect(&hex, now).unwrap();
        assert!(text.contains("trailing data     4 uninterpreted byte(s)"));
    }

    #[test]
    fn inspect_rejects_short_input() {
        let now = NtpInstant::from_unix_nanos(0);
        assert!(inspect("2300", now).is_err());
    }
}
