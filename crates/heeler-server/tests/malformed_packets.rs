//! Hostile-input integration tests: nothing here may crash the server or
//! draw an unexpected response.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::{client_request, exchange, exchange_parsed, test_config, test_instant, TestServer};
use heeler_core::clock::MockClockSource;
use heeler_core::packet::PACKET_SIZE;

fn clock() -> Arc<MockClockSource> {
    Arc::new(MockClockSource::fixed(test_instant()))
}

/// After every hostile probe the server must still answer a valid request.
async fn assert_alive(server: &TestServer) {
    assert!(
        exchange_parsed(server.addr(), &client_request(4, 3, 0xA11CE))
            .await
            .is_some(),
        "server must still respond after hostile input"
    );
}

#[tokio::test]
async fn short_packets_are_ignored() {
    let server = TestServer::start(test_config(), clock()).await;
    for len in [0usize, 1, 12, 47] {
        let junk = vec![0x23u8; len];
        assert!(
            exchange(server.addr(), &junk).await.is_none(),
            "{len}-byte packet must not be answered"
        );
    }
    assert!(
        server
            .state
            .metrics
            .malformed_packets_total
            .load(Ordering::Relaxed)
            >= 3,
        "short packets must be counted as malformed"
    );
    assert_alive(&server).await;
    server.stop().await;
}

#[tokio::test]
async fn oversized_datagrams_are_dropped() {
    let mut config = test_config();
    config.server.max_packet_size = 96;
    let server = TestServer::start(config, clock()).await;
    let mut big = vec![0u8; 200];
    big[..48].copy_from_slice(&client_request(4, 3, 77));
    assert!(exchange(server.addr(), &big).await.is_none());
    assert_alive(&server).await;
    server.stop().await;
}

#[tokio::test]
async fn trailing_data_policy_is_enforced() {
    // Default: trailing bytes are rejected.
    let server = TestServer::start(test_config(), clock()).await;
    let mut data = client_request(4, 3, 55).to_vec();
    data.extend_from_slice(&[0xAB; 4]);
    assert!(exchange(server.addr(), &data).await.is_none());
    assert_alive(&server).await;
    server.stop().await;

    // Opt-in: the base packet is answered, trailing bytes ignored.
    let mut config = test_config();
    config.protocol.allow_trailing_data = true;
    let server = TestServer::start(config, clock()).await;
    let response = exchange_parsed(server.addr(), &data)
        .await
        .expect("trailing data accepted when configured");
    assert_eq!(response.packet.encode().len(), PACKET_SIZE);
    server.stop().await;
}

#[tokio::test]
async fn non_client_modes_are_never_answered() {
    let server = TestServer::start(test_config(), clock()).await;
    // Reserved, symmetric active/passive, server, broadcast, control,
    // private — none may draw a response (reflection resistance).
    for mode in [0u8, 1, 2, 4, 5, 6, 7] {
        assert!(
            exchange(server.addr(), &client_request(4, mode, 1))
                .await
                .is_none(),
            "mode {mode} must not be answered"
        );
    }
    assert_eq!(
        server
            .state
            .metrics
            .unsupported_mode_total
            .load(Ordering::Relaxed),
        7
    );
    assert_alive(&server).await;
    server.stop().await;
}

#[tokio::test]
async fn unsupported_versions_are_ignored() {
    let server = TestServer::start(test_config(), clock()).await;
    for version in [0u8, 1, 2, 5, 6, 7] {
        assert!(
            exchange(server.addr(), &client_request(version, 3, 1))
                .await
                .is_none(),
            "version {version} must not be answered"
        );
    }
    assert_eq!(
        server
            .state
            .metrics
            .unsupported_version_total
            .load(Ordering::Relaxed),
        6
    );
    assert_alive(&server).await;
    server.stop().await;
}

#[tokio::test]
async fn zero_transmit_timestamp_policy() {
    // Compatible by default (SNTP clients may send all-zero fields).
    let server = TestServer::start(test_config(), clock()).await;
    assert!(exchange_parsed(server.addr(), &client_request(4, 3, 0))
        .await
        .is_some());
    server.stop().await;

    // Strict mode rejects them.
    let mut config = test_config();
    config.protocol.require_nonzero_transmit_timestamp = true;
    let server = TestServer::start(config, clock()).await;
    assert!(exchange(server.addr(), &client_request(4, 3, 0))
        .await
        .is_none());
    assert_alive(&server).await;
    server.stop().await;
}

#[tokio::test]
async fn random_garbage_never_kills_the_server() {
    let server = TestServer::start(test_config(), clock()).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Deterministic xorshift so the test is reproducible. Fire everything,
    // then drain whatever comes back: any reply must be a well-formed
    // 48-byte packet (random bytes can form a legitimate v3/v4 request).
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    for len in [1usize, 47, 48, 49, 64, 96] {
        for _ in 0..50 {
            let mut payload = vec![0u8; len];
            for byte in &mut payload {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed as u8;
            }
            socket.send_to(&payload, server.addr()).await.unwrap();
        }
    }
    let mut buf = [0u8; 1024];
    while let Ok(Ok((len, _))) = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        socket.recv_from(&mut buf),
    )
    .await
    {
        assert_eq!(len, PACKET_SIZE, "any reply must be a base packet");
    }
    assert_alive(&server).await;
    server.stop().await;
}
