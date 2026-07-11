//! Protocol integration tests against a live server on an ephemeral port.

mod common;

use std::sync::Arc;

use common::{client_request, exchange, exchange_parsed, test_config, test_instant, TestServer};
use heeler_core::clock::{ClockStatus, MockClockSource, SystemClockSource};
use heeler_core::packet::{LeapIndicator, Mode, PACKET_SIZE};
use heeler_core::timestamp::NtpTimestamp;

fn mock_clock() -> Arc<MockClockSource> {
    let clock = Arc::new(MockClockSource::fixed(test_instant()));
    clock.set_reference_timestamp(Some(NtpTimestamp::new(0xE900_0000, 0)));
    clock
}

#[tokio::test]
async fn v4_request_gets_correct_response() {
    let clock = mock_clock();
    let server = TestServer::start(test_config(), clock).await;

    let transmit = 0xE3B0_F2AC_8000_0000u64;
    let response = exchange_parsed(server.addr(), &client_request(4, 3, transmit))
        .await
        .expect("response expected");
    let p = response.packet;
    assert_eq!(p.mode, Mode::Server);
    assert_eq!(p.version.to_bits(), 4);
    assert_eq!(p.leap, LeapIndicator::NoWarning);
    assert_eq!(p.stratum.value(), 2);
    assert_eq!(p.reference_id.as_bytes(), *b"HLER");
    // Origin must echo the client transmit timestamp exactly.
    assert_eq!(p.origin_timestamp, NtpTimestamp::from_bits(transmit));
    // T2/T3 come from the mock instant, not from client data.
    let expected = test_instant().to_timestamp().unwrap();
    assert_eq!(p.receive_timestamp, expected);
    assert_eq!(p.transmit_timestamp, expected);
    // Reference timestamp is the configured "last valid" time, not now.
    assert_eq!(p.reference_timestamp, NtpTimestamp::new(0xE900_0000, 0));
    assert_eq!(response.trailing_bytes, 0);

    server.stop().await;
}

#[tokio::test]
async fn v3_request_mirrors_version() {
    let server = TestServer::start(test_config(), mock_clock()).await;
    let response = exchange_parsed(server.addr(), &client_request(3, 3, 1))
        .await
        .expect("response expected");
    assert_eq!(response.packet.version.to_bits(), 3);
    assert_eq!(response.packet.mode, Mode::Server);
    server.stop().await;
}

#[tokio::test]
async fn ipv6_loopback_is_served() {
    // Skip (with a note) in environments without an IPv6 stack.
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("skipping: IPv6 is unavailable in this environment");
        return;
    }
    let mut config = test_config();
    config.server.bind = vec!["[::1]:0".parse().unwrap()];
    let server = TestServer::start(config, mock_clock()).await;
    let response = exchange_parsed(server.addr(), &client_request(4, 3, 7))
        .await
        .expect("IPv6 response expected");
    assert_eq!(response.packet.mode, Mode::Server);
    server.stop().await;
}

#[tokio::test]
async fn distinct_receive_and_transmit_timestamps() {
    // Scripted clock: T2 then T3 differ by 1 ms; the server must use two
    // separate readings, never one captured value for both.
    let t2 = test_instant();
    let t3 = t2.add_nanos(1_000_000);
    let clock = Arc::new(MockClockSource::new(vec![Ok(t2), Ok(t3)]));
    clock.set_reference_timestamp(Some(NtpTimestamp::new(1, 0)));
    let server = TestServer::start(test_config(), clock).await;

    let response = exchange_parsed(server.addr(), &client_request(4, 3, 42))
        .await
        .expect("response expected");
    assert_eq!(
        response.packet.receive_timestamp,
        t2.to_timestamp().unwrap()
    );
    assert_eq!(
        response.packet.transmit_timestamp,
        t3.to_timestamp().unwrap()
    );
    assert_ne!(
        response.packet.receive_timestamp,
        response.packet.transmit_timestamp
    );
    server.stop().await;
}

#[tokio::test]
async fn unsynchronised_clock_reports_alarm() {
    let clock = mock_clock();
    clock.set_status(ClockStatus::Unsynchronised);
    let server = TestServer::start(test_config(), clock).await;
    let response = exchange_parsed(server.addr(), &client_request(4, 3, 9))
        .await
        .expect("response expected");
    assert_eq!(response.packet.leap, LeapIndicator::Unsynchronised);
    assert_eq!(response.packet.stratum.value(), 16);
    server.stop().await;
}

#[tokio::test]
async fn clock_failure_drops_request_without_crashing() {
    let clock = Arc::new(MockClockSource::new(vec![Err(
        heeler_core::error::ClockError::SystemClock("scripted failure".into()),
    )]));
    let server = TestServer::start(test_config(), clock).await;
    assert!(
        exchange(server.addr(), &client_request(4, 3, 5))
            .await
            .is_none(),
        "no response when the clock cannot be read"
    );
    server.stop().await;
}

#[tokio::test]
async fn rate_limit_sends_kod_then_recovers_metadata() {
    let mut config = test_config();
    config.rate_limit.enabled = true;
    config.rate_limit.requests_per_second = 1;
    config.rate_limit.burst = 1;
    let server = TestServer::start(config, mock_clock()).await;

    let first = exchange_parsed(server.addr(), &client_request(4, 3, 100))
        .await
        .expect("first request within burst");
    assert_eq!(first.packet.stratum.value(), 2);

    let second = exchange_parsed(server.addr(), &client_request(4, 3, 101))
        .await
        .expect("second request draws a KoD");
    assert!(second.packet.stratum.is_kiss_of_death());
    assert_eq!(second.packet.reference_id.as_bytes(), *b"RATE");
    assert_eq!(second.packet.mode, Mode::Server);
    // KoD still echoes the origin so the client can match it.
    assert_eq!(second.packet.origin_timestamp, NtpTimestamp::from_bits(101));
    server.stop().await;
}

#[tokio::test]
async fn global_rate_limit_drops_silently() {
    let mut config = test_config();
    config.rate_limit.enabled = true;
    config.rate_limit.requests_per_second = 100;
    config.rate_limit.burst = 100;
    config.rate_limit.global_requests_per_second = 1;
    config.rate_limit.global_burst = 1;
    let server = TestServer::start(config, mock_clock()).await;

    assert!(exchange(server.addr(), &client_request(4, 3, 1))
        .await
        .is_some());
    assert!(
        exchange(server.addr(), &client_request(4, 3, 2))
            .await
            .is_none(),
        "global limit must drop, never reflect"
    );
    server.stop().await;
}

#[tokio::test]
async fn access_denied_is_silent_by_default() {
    let mut config = test_config();
    config.access.allow = vec!["192.0.2.1/32".to_owned()]; // not loopback
    let server = TestServer::start(config, mock_clock()).await;
    assert!(exchange(server.addr(), &client_request(4, 3, 3))
        .await
        .is_none());
    assert_eq!(
        server
            .state
            .metrics
            .access_denied_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    server.stop().await;
}

#[tokio::test]
async fn access_denied_kod_when_configured() {
    let mut config = test_config();
    config.access.allow = vec!["192.0.2.1/32".to_owned()];
    config.protocol.send_kod_on_policy_deny = true;
    let server = TestServer::start(config, mock_clock()).await;
    let response = exchange_parsed(server.addr(), &client_request(4, 3, 4))
        .await
        .expect("DENY KoD expected");
    assert!(response.packet.stratum.is_kiss_of_death());
    assert_eq!(response.packet.reference_id.as_bytes(), *b"DENY");
    server.stop().await;
}

#[tokio::test]
async fn system_clock_source_end_to_end() {
    // Full path with the real system clock: T2 <= T3, both near now.
    let clock = Arc::new(
        SystemClockSource::new(Default::default(), std::time::Duration::from_millis(5))
            .expect("system clock"),
    );
    let server = TestServer::start(test_config(), clock).await;
    let response = exchange_parsed(server.addr(), &client_request(4, 3, 11))
        .await
        .expect("response expected");
    let p = response.packet;
    assert_eq!(p.leap, LeapIndicator::NoWarning);
    let t2 = p.receive_timestamp.to_bits();
    let t3 = p.transmit_timestamp.to_bits();
    assert!(t3 >= t2, "transmit must not precede receive");
    assert!(!p.reference_timestamp.is_zero());
    server.stop().await;
}

#[tokio::test]
async fn graceful_shutdown_stops_serving() {
    let server = TestServer::start(test_config(), mock_clock()).await;
    let addr = server.addr();
    assert!(exchange(addr, &client_request(4, 3, 1)).await.is_some());
    server.stop().await; // asserts prompt, clean exit internally
    assert!(
        exchange(addr, &client_request(4, 3, 2)).await.is_none(),
        "stopped server must not respond"
    );
}

#[tokio::test]
async fn metrics_endpoint_serves_counters() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let clock = mock_clock();
    let server = TestServer::start(test_config(), clock).await;
    exchange(server.addr(), &client_request(4, 3, 8)).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_addr = listener.local_addr().unwrap();
    let (_tx, rx) = heeler_server::shutdown::channel();
    tokio::spawn(heeler_server::metrics::serve_metrics(
        listener,
        server.state.metrics.clone(),
        rx,
    ));

    let mut stream = tokio::net::TcpStream::connect(metrics_addr).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nhost: test\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    let _ = stream.read_to_string(&mut body).await;
    assert!(body.starts_with("HTTP/1.1 200 OK"));
    assert!(body.contains("heeler_requests_total 1"));
    assert!(body.contains("heeler_responses_total 1"));

    // Anything else is a 404.
    let mut stream = tokio::net::TcpStream::connect(metrics_addr).await.unwrap();
    stream
        .write_all(b"GET /secrets HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    let _ = stream.read_to_string(&mut body).await;
    assert!(body.starts_with("HTTP/1.1 404"));

    server.stop().await;
}

#[test]
fn responses_are_never_larger_than_the_base_packet() {
    // Static guarantee exercised at type level: encode() returns [u8; 48].
    assert_eq!(PACKET_SIZE, 48);
}
