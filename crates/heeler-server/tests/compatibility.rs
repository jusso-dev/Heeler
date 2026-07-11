//! Client-compatibility integration tests.
//!
//! These exercise the request shapes that common clients actually send,
//! plus Heeler's own diagnostic client against a live server.
//!
//! # Testing against external clients
//!
//! Where the tools are installed, a Heeler instance on port 11123 can be
//! probed manually (none of these are required by the test suite):
//!
//! ```text
//! sntp -d 127.0.0.1                    # macOS/BSD sntp (port 123 only)
//! ntpdate -q -p 1 127.0.0.1            # query-only mode
//! chronyd -Q -t 2 'server 127.0.0.1 iburst maxsources 1'
//! ntpq -c "rv 0" 127.0.0.1             # note: control mode is refused by
//!                                      # design; expect a timeout
//! ```
//!
//! `systemd-timesyncd` can be pointed at Heeler with `NTP=<host>` in
//! `/etc/systemd/timesyncd.conf`.

mod common;

use std::sync::Arc;

use common::{exchange_parsed, test_config, test_instant, TestServer};
use heeler_core::clock::MockClockSource;
use heeler_core::packet::{Mode, PACKET_SIZE};

fn clock() -> Arc<MockClockSource> {
    let clock = Arc::new(MockClockSource::fixed(test_instant()));
    clock.set_reference_timestamp(Some(heeler_core::timestamp::NtpTimestamp::new(
        0xE900_0000,
        0,
    )));
    clock
}

/// Minimal SNTP request: only the flags byte set, everything else zero.
/// This is the classic `sntp`/embedded-client shape.
#[tokio::test]
async fn minimal_sntp_v4_request() {
    let server = TestServer::start(test_config(), clock()).await;
    let mut request = [0u8; PACKET_SIZE];
    request[0] = 0x23; // LI=0 VN=4 mode=3
    let response = exchange_parsed(server.addr(), &request)
        .await
        .expect("minimal SNTP request must be served");
    let p = response.packet;
    assert_eq!(p.mode, Mode::Server);
    assert_eq!(p.version.to_bits(), 4);
    assert!(
        p.origin_timestamp.is_zero(),
        "origin echoes the zero transmit"
    );
    assert!(!p.transmit_timestamp.is_zero());
    server.stop().await;
}

/// Old-style NTPv3 request as sent by `ntpdate` and many embedded stacks.
#[tokio::test]
async fn ntpdate_style_v3_request() {
    let server = TestServer::start(test_config(), clock()).await;
    let mut request = [0u8; PACKET_SIZE];
    request[0] = 0x1B; // LI=0 VN=3 mode=3
    request[2] = 4; // poll as ntpdate sends
    request[3] = 0xFA_u8; // precision -6
    request[40..48].copy_from_slice(&[0xEB, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE]);
    let response = exchange_parsed(server.addr(), &request)
        .await
        .expect("ntpdate-style request must be served");
    let p = response.packet;
    assert_eq!(p.version.to_bits(), 3);
    assert_eq!(p.mode, Mode::Server);
    assert_eq!(
        p.origin_timestamp.to_bits(),
        0xEB12_3456_789A_BCDE,
        "origin must echo the client transmit timestamp"
    );
    assert_eq!(p.poll, 4, "in-range client poll is echoed");
    server.stop().await;
}

/// chrony sends v4 client requests with its own transmit timestamp and a
/// random-looking fraction; ensure fraction bits round-trip untouched.
#[tokio::test]
async fn chrony_style_v4_request_preserves_fraction_bits() {
    let server = TestServer::start(test_config(), clock()).await;
    let mut request = [0u8; PACKET_SIZE];
    request[0] = 0x23;
    request[2] = 6;
    // chrony randomises the low bits of the transmit timestamp as an
    // anti-spoofing cookie: they must come back bit-exact.
    let cookie = 0xEB77_1122_DEAD_BEEFu64;
    request[40..48].copy_from_slice(&cookie.to_be_bytes());
    let response = exchange_parsed(server.addr(), &request)
        .await
        .expect("chrony-style request must be served");
    assert_eq!(response.packet.origin_timestamp.to_bits(), cookie);
    server.stop().await;
}

/// Heeler's own diagnostic client against a live Heeler server.
#[tokio::test]
async fn heeler_query_client_round_trip() {
    // The real system clock on both ends so offset ≈ 0 over loopback.
    let clock = Arc::new(
        heeler_core::clock::SystemClockSource::new(
            Default::default(),
            std::time::Duration::from_millis(5),
        )
        .expect("system clock"),
    );
    let server = TestServer::start(test_config(), clock).await;
    let addr = server.addr();

    let report = tokio::task::spawn_blocking(move || {
        heeler_server::client::query(&heeler_server::client::QueryOptions {
            server: addr.to_string(),
            version: 4,
            timeout: std::time::Duration::from_secs(2),
        })
    })
    .await
    .expect("query task")
    .expect("query must succeed");

    assert!(
        report.origin_matched,
        "server must echo our transmit timestamp"
    );
    assert_eq!(report.response.stratum.value(), 2);
    // Loopback to the same clock: offset and delay are tiny. Allow a wide
    // margin for CI scheduling noise.
    assert!(
        report.delay_nanos.abs() < 500_000_000,
        "loopback delay {} ns",
        report.delay_nanos
    );
    assert!(
        report.offset_nanos.abs() < 250_000_000,
        "same-clock offset {} ns",
        report.offset_nanos
    );
    assert!(report.t4.nanos_since(report.t1) >= 0);
    server.stop().await;
}
