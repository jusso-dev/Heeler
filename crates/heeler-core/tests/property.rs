//! Property-based tests for the wire format and timestamp arithmetic.

use proptest::prelude::*;

use heeler_core::packet::{NtpPacket, NtpShortSigned, NtpShortUnsigned, PACKET_SIZE};
use heeler_core::timestamp::{NtpInstant, NtpTimestamp};

proptest! {
    /// Parsing any 48-byte buffer succeeds and re-encodes to the identical
    /// bytes: the base packet has no invalid bit patterns.
    #[test]
    fn parse_encode_is_identity_on_wire(data in prop::array::uniform32(any::<u8>()),
                                        tail in prop::array::uniform16(any::<u8>())) {
        let mut packet = [0u8; PACKET_SIZE];
        packet[..32].copy_from_slice(&data);
        packet[32..].copy_from_slice(&tail);
        let parsed = NtpPacket::parse(&packet).unwrap();
        prop_assert_eq!(parsed.packet.encode(), packet);
        prop_assert_eq!(parsed.trailing_bytes, 0);
    }

    /// The parser never panics on arbitrary input of arbitrary length.
    #[test]
    fn parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let result = NtpPacket::parse(&data);
        if data.len() >= PACKET_SIZE {
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap().trailing_bytes, data.len() - PACKET_SIZE);
        } else {
            prop_assert!(result.is_err());
        }
    }

    /// Timestamp wire encoding round-trips through bytes and bits.
    #[test]
    fn timestamp_wire_round_trip(seconds in any::<u32>(), fraction in any::<u32>()) {
        let ts = NtpTimestamp::new(seconds, fraction);
        prop_assert_eq!(NtpTimestamp::from_be_bytes(ts.to_be_bytes()), ts);
        prop_assert_eq!(NtpTimestamp::from_bits(ts.to_bits()), ts);
    }

    /// Fraction conversion round-trips within one unit of quantisation and
    /// stays within bounds.
    #[test]
    fn fraction_conversion_bounds(nanos in 0u32..1_000_000_000) {
        let fraction = NtpTimestamp::fraction_from_nanos(nanos);
        let back = NtpTimestamp::fraction_to_nanos(fraction);
        prop_assert!(back < 1_000_000_000);
        prop_assert!(back <= nanos);
        prop_assert!(nanos - back <= 1);
    }

    /// Era unfolding inverts encoding for any instant within ±68 years of
    /// the pivot (the guaranteed-unambiguous window).
    #[test]
    fn unfold_inverts_encoding_near_pivot(
        // Unix seconds from 1970 to ~2150, covering the 2036 rollover.
        pivot_unix in 0i64..5_700_000_000,
        offset_seconds in -2_000_000_000i64..2_000_000_000,
        nanos in 0u32..1_000_000_000,
    ) {
        let pivot = NtpInstant::from_unix_nanos(i128::from(pivot_unix) * 1_000_000_000);
        let instant = pivot
            .add_nanos(i128::from(offset_seconds) * 1_000_000_000)
            .add_nanos(i128::from(nanos));
        prop_assume!(instant.as_ntp_nanos() >= 0); // encodable instants only
        let ts = instant.to_timestamp().unwrap();
        let unfolded = ts.unfold(pivot);
        // Seconds resolve exactly; the fraction re-quantises within 1 ns.
        let error = (unfolded.nanos_since(instant)).abs();
        prop_assert!(error <= 1, "error {error} ns");
    }

    /// 16.16 fixed-point wire encoding round-trips.
    #[test]
    fn ntp_short_round_trip(bits in any::<i32>(), ubits in any::<u32>()) {
        let signed = NtpShortSigned::from_bits(bits);
        prop_assert_eq!(NtpShortSigned::from_be_bytes(signed.to_be_bytes()), signed);
        let unsigned = NtpShortUnsigned::from_bits(ubits);
        prop_assert_eq!(NtpShortUnsigned::from_be_bytes(unsigned.to_be_bytes()), unsigned);
    }

    /// Millisecond construction of fixed-point fields stays within one
    /// microsecond-per-millisecond of the requested value.
    #[test]
    fn ntp_short_millis_accuracy(millis in 0i64..32_000_000) {
        let value = NtpShortUnsigned::from_millis(millis).unwrap();
        let micros = value.to_micros();
        let target = millis as u64 * 1000;
        prop_assert!(micros <= target);
        prop_assert!(target - micros <= 16); // one 2^-16 s unit ≈ 15.26 µs
    }

    /// SystemTime conversion round-trips for representable instants.
    #[test]
    fn system_time_round_trip(unix_secs in -2_000_000_000i64..5_000_000_000, nanos in 0u32..1_000_000_000) {
        let instant = NtpInstant::from_unix_nanos(
            i128::from(unix_secs) * 1_000_000_000 + i128::from(nanos),
        );
        let system = instant.to_system_time().unwrap();
        prop_assert_eq!(NtpInstant::from_system_time(system), instant);
    }
}
