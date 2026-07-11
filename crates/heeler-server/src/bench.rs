//! `heeler bench`: honest software-level micro-benchmarks.
//!
//! Measures packet parsing, encoding, timestamp conversion, and response
//! construction on this machine using the monotonic clock. These numbers
//! describe CPU cost only — they say **nothing** about time accuracy, which
//! is bounded by host clock quality, scheduling, and the network path. For
//! an end-to-end loopback measurement run `heeler serve` and `heeler query
//! 127.0.0.1:<port>`.

use std::time::{Instant, SystemTime};

use heeler_core::clock::ClockStatus;
use heeler_core::packet::{
    LeapIndicator, NtpPacket, NtpShortSigned, NtpShortUnsigned, ReferenceId, Stratum,
};
use heeler_core::response::{build_response, ServerIdentity};
use heeler_core::timestamp::{NtpInstant, NtpTimestamp};

const REQUEST: [u8; 48] = [
    0x23, 0x00, 0x06, 0xEC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xE3, 0xB0, 0xF2, 0xAC, 0x80, 0x00, 0x00, 0x00,
];

/// Runs every micro-benchmark and returns a formatted report.
#[must_use]
pub fn run() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Heeler micro-benchmarks (software cost only)");
    let _ = writeln!(out);

    let iterations = 1_000_000u64;

    let parse_ns = measure(iterations, || {
        let parsed = NtpPacket::parse(std::hint::black_box(&REQUEST));
        std::hint::black_box(parsed).is_ok()
    });
    let _ = writeln!(out, "packet parse               {parse_ns:>8.1} ns/op");

    let packet = match NtpPacket::parse(&REQUEST) {
        Ok(parsed) => parsed.packet,
        Err(_) => return "internal error: benchmark request invalid".to_owned(),
    };
    let encode_ns = measure(iterations, || {
        std::hint::black_box(std::hint::black_box(&packet).encode())[0] == 0x23
    });
    let _ = writeln!(out, "packet encode              {encode_ns:>8.1} ns/op");

    let clock_ns = measure(iterations, || {
        NtpInstant::from_system_time(std::hint::black_box(SystemTime::now())).as_ntp_nanos() > 0
    });
    let _ = writeln!(out, "system clock read          {clock_ns:>8.1} ns/op");

    let convert_ns = measure(iterations, || {
        let instant =
            NtpInstant::from_unix_nanos(std::hint::black_box(1_700_000_000_123_456_789i128));
        instant.to_timestamp().is_ok()
    });
    let _ = writeln!(out, "timestamp conversion       {convert_ns:>8.1} ns/op");

    let identity = ServerIdentity {
        stratum: Stratum::from_raw(2),
        reference_id: ReferenceId::DEFAULT,
        precision: -20,
        root_delay: NtpShortSigned::ZERO,
        root_dispersion: NtpShortUnsigned::from_bits(327),
        default_poll: 6,
        leap: LeapIndicator::NoWarning,
    };
    let t2 = NtpTimestamp::new(0xE3B0_F2AD, 0x1000_0000);
    let build_ns = measure(iterations, || {
        let response = build_response(
            std::hint::black_box(&packet),
            &identity,
            ClockStatus::Synchronised,
            NtpTimestamp::new(0xE3B0_F000, 0),
            t2,
        );
        std::hint::black_box(response).poll == 6
    });
    let _ = writeln!(out, "response build             {build_ns:>8.1} ns/op");

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "note: these measure CPU cost, not time accuracy. Served accuracy is"
    );
    let _ = writeln!(
        out,
        "bounded by host clock quality and synchronisation, kernel scheduling,"
    );
    let _ = write!(
        out,
        "network latency and asymmetry, virtualisation, and CPU power management."
    );
    out
}

fn measure(iterations: u64, mut op: impl FnMut() -> bool) -> f64 {
    // Warm up.
    for _ in 0..10_000 {
        std::hint::black_box(op());
    }
    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(op());
    }
    start.elapsed().as_nanos() as f64 / iterations as f64
}

#[cfg(test)]
mod tests {
    #[test]
    fn bench_runs() {
        // Smoke test with the tiny iteration count hidden behind the public
        // API being deterministic enough: just ensure the report renders.
        let report = super::run();
        assert!(report.contains("packet parse"));
        assert!(report.contains("response build"));
    }
}
