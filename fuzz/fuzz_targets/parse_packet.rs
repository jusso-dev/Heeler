//! Fuzz target: the full untrusted-input surface of heeler-core.
//!
//! Feeds arbitrary bytes through parsing, validation, response and KoD
//! building, re-encoding, and timestamp era unfolding. Any panic is a bug:
//! the parser and everything downstream of it must be total over arbitrary
//! input.
//!
//! Run with: `cargo +nightly fuzz run parse_packet` (from the repo root).

#![no_main]

use heeler_core::clock::ClockStatus;
use heeler_core::packet::{
    KissCode, LeapIndicator, NtpPacket, NtpShortSigned, NtpShortUnsigned, ReferenceId, Stratum,
    PACKET_SIZE,
};
use heeler_core::response::{build_kiss_of_death, build_response, ServerIdentity};
use heeler_core::timestamp::{NtpInstant, NtpTimestamp};
use heeler_core::validation::ValidationPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = NtpPacket::parse(data) else {
        assert!(data.len() < PACKET_SIZE);
        return;
    };
    assert_eq!(parsed.trailing_bytes, data.len() - PACKET_SIZE);

    // Re-encoding the base packet must reproduce the input bytes exactly.
    assert_eq!(parsed.packet.encode(), data[..PACKET_SIZE]);

    // Validation must be total under both lenient and strict policies.
    let lenient = ValidationPolicy {
        supported_versions: vec![3, 4],
        require_nonzero_transmit_timestamp: false,
        allow_trailing_data: true,
    };
    let strict = ValidationPolicy {
        supported_versions: vec![4],
        require_nonzero_transmit_timestamp: true,
        allow_trailing_data: false,
    };
    let _ = strict.validate(&parsed);

    // Timestamp era unfolding must be total for any wire timestamp against
    // pivots on both sides of the 2036 rollover.
    for pivot_unix in [0i128, 1_767_225_600, 2_085_978_496, 3_000_000_000] {
        let pivot = NtpInstant::from_unix_nanos(pivot_unix * 1_000_000_000);
        let _ = parsed.packet.transmit_timestamp.unfold(pivot);
        let _ = parsed.packet.origin_timestamp.unfold(pivot);
    }

    // Response and KoD building must be total for any accepted request.
    if lenient.validate(&parsed).is_ok() {
        let identity = ServerIdentity {
            stratum: Stratum::from_raw(2),
            reference_id: ReferenceId::DEFAULT,
            precision: -20,
            root_delay: NtpShortSigned::ZERO,
            root_dispersion: NtpShortUnsigned::from_bits(327),
            default_poll: 6,
            leap: LeapIndicator::NoWarning,
        };
        let t2 = NtpTimestamp::new(0xEB00_0000, 0x8000_0000);
        for status in [ClockStatus::Synchronised, ClockStatus::Unsynchronised] {
            let response = build_response(&parsed.packet, &identity, status, t2, t2);
            assert_eq!(response.encode().len(), PACKET_SIZE);
            // The only client-controlled field in a response is the origin
            // echo of the transmit timestamp.
            assert_eq!(response.origin_timestamp, parsed.packet.transmit_timestamp);
        }
        let kod = build_kiss_of_death(&parsed.packet, KissCode::Rate, t2);
        assert!(kod.stratum.is_kiss_of_death());
        assert_eq!(kod.encode().len(), PACKET_SIZE);
    }
});
