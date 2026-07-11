//! Concurrency integration tests: many simultaneous clients, no
//! cross-contamination, stable counters.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::{test_config, test_instant, TestServer};
use heeler_core::clock::MockClockSource;
use heeler_core::packet::{Mode, NtpPacket, PACKET_SIZE};
use heeler_core::timestamp::NtpTimestamp;

const CLIENTS: u64 = 32;
const REQUESTS_PER_CLIENT: u64 = 25;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_clients_get_their_own_origins() {
    let clock = Arc::new(MockClockSource::fixed(test_instant()));
    let server = TestServer::start(test_config(), clock).await;
    let addr = server.addr();

    let mut tasks = Vec::new();
    for client_id in 0..CLIENTS {
        tasks.push(tokio::spawn(async move {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(addr).await.unwrap();
            let mut ok = 0u64;
            for seq in 0..REQUESTS_PER_CLIENT {
                // A transmit timestamp unique to (client, request).
                let marker = (client_id << 32) | (seq + 1);
                let mut request = [0u8; PACKET_SIZE];
                request[0] = (4 << 3) | 3;
                request[40..48].copy_from_slice(&marker.to_be_bytes());
                socket.send(&request).await.unwrap();

                let mut buf = [0u8; 1024];
                let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
                    .await
                    .expect("no response within 2 s")
                    .expect("recv failed");
                assert_eq!(len, PACKET_SIZE);
                let response = NtpPacket::parse(&buf[..len]).unwrap().packet;
                assert_eq!(response.mode, Mode::Server);
                // The origin echo must be exactly this request's marker:
                // any mix-up between concurrent clients is a hard failure.
                assert_eq!(
                    response.origin_timestamp,
                    NtpTimestamp::from_bits(marker),
                    "origin cross-contamination for client {client_id} seq {seq}"
                );
                ok += 1;
            }
            ok
        }));
    }

    let mut total = 0;
    for task in tasks {
        total += task.await.expect("client task must not panic");
    }
    assert_eq!(total, CLIENTS * REQUESTS_PER_CLIENT);

    let metrics = &server.state.metrics;
    assert_eq!(
        metrics.requests_total.load(Ordering::Relaxed),
        CLIENTS * REQUESTS_PER_CLIENT
    );
    assert_eq!(
        metrics.responses_total.load(Ordering::Relaxed),
        CLIENTS * REQUESTS_PER_CLIENT
    );
    assert_eq!(metrics.packets_dropped_total.load(Ordering::Relaxed), 0);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flood_with_rate_limit_stays_bounded_and_alive() {
    let mut config = test_config();
    config.rate_limit.enabled = true;
    config.rate_limit.requests_per_second = 10;
    config.rate_limit.burst = 20;
    // Everything comes from 127.0.0.1, so one tracked entry.
    let clock = Arc::new(MockClockSource::fixed(test_instant()));
    let server = TestServer::start(config, clock).await;
    let addr = server.addr();

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut request = [0u8; PACKET_SIZE];
    request[0] = (4 << 3) | 3;
    for i in 0..500u64 {
        request[40..48].copy_from_slice(&i.to_be_bytes());
        socket.send_to(&request, addr).await.unwrap();
    }
    // Drain replies; under a flood most must be dropped or KoD.
    let mut replies = 0u64;
    let mut buf = [0u8; 1024];
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await
    {
        replies += 1;
    }
    assert!(
        replies < 100,
        "rate limiter must curb a flood (got {replies})"
    );
    assert!(server.state.limiter.active_entries() <= 1);
    assert!(
        server
            .state
            .metrics
            .rate_limited_total
            .load(Ordering::Relaxed)
            > 300,
        "most of the flood must be rate-limited"
    );

    // And the server still works afterwards for a well-behaved client
    // (after the bucket refills).
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut fresh = [0u8; PACKET_SIZE];
    fresh[0] = (4 << 3) | 3;
    fresh[40] = 1;
    socket.send_to(&fresh, addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await;
    assert!(got.is_ok(), "server must recover after the flood");

    server.stop().await;
}
