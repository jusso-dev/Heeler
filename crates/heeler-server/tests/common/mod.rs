//! Shared harness: runs a real Heeler server on an ephemeral loopback port.

// Each test binary compiles this module separately and uses a different
// subset of the helpers.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use heeler_core::clock::ClockSource;
use heeler_core::packet::{NtpPacket, ParsedPacket, PACKET_SIZE};
use heeler_core::timestamp::NtpInstant;
use heeler_server::config::Config;
use heeler_server::server::{bind_sockets, run_server, ServerState};
use heeler_server::shutdown;
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// A 2026-era test instant (Unix 1 767 225 600 = 2026-01-01T00:00:00Z).
pub fn test_instant() -> NtpInstant {
    NtpInstant::from_unix_nanos(1_767_225_600 * 1_000_000_000)
}

pub struct TestServer {
    pub addrs: Vec<SocketAddr>,
    pub state: Arc<ServerState>,
    shutdown_tx: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl TestServer {
    /// Starts a server with the given config (bind addresses should use
    /// port 0) and clock source.
    pub async fn start(config: Config, clock: Arc<dyn ClockSource>) -> Self {
        let validated = config.validate().expect("test config must validate");
        let sockets = bind_sockets(&validated.config.server).expect("bind test sockets");
        let addrs = sockets
            .iter()
            .map(|s| s.local_addr().expect("local addr"))
            .collect();
        let state = Arc::new(ServerState::new(&validated, clock, None));
        let (shutdown_tx, shutdown_rx) = shutdown::channel();
        let handle = tokio::spawn(run_server(state.clone(), sockets, shutdown_rx));
        // Give the receive loops a beat to come up.
        tokio::time::sleep(Duration::from_millis(20)).await;
        Self {
            addrs,
            state,
            shutdown_tx,
            handle,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addrs[0]
    }

    /// Signals shutdown and waits for every loop to stop.
    pub async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        let joined = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
        joined
            .expect("server must shut down promptly")
            .expect("server task must not panic")
            .expect("server must exit cleanly");
    }
}

/// A default test configuration: ephemeral loopback bind, loopback-only
/// access, rate limiting off (individual tests re-enable what they probe).
pub fn test_config() -> Config {
    let mut config = Config::default();
    config.server.bind = vec!["127.0.0.1:0".parse().expect("addr")];
    config.rate_limit.enabled = false;
    config
}

/// Builds a raw client request with the given version/mode and a
/// recognisable transmit timestamp.
pub fn client_request(version: u8, mode: u8, transmit: u64) -> [u8; PACKET_SIZE] {
    let mut data = [0u8; PACKET_SIZE];
    data[0] = (version << 3) | mode;
    data[2] = 6; // poll
    data[40..48].copy_from_slice(&transmit.to_be_bytes());
    data
}

/// Sends `payload` to `server` from a fresh ephemeral socket and awaits one
/// response.
pub async fn exchange(server: SocketAddr, payload: &[u8]) -> Option<(Vec<u8>, SocketAddr)> {
    let bind: SocketAddr = if server.is_ipv4() {
        "127.0.0.1:0".parse().expect("addr")
    } else {
        "[::1]:0".parse().expect("addr")
    };
    let socket = UdpSocket::bind(bind).await.expect("bind client");
    socket.send_to(payload, server).await.expect("send");
    let mut buf = [0u8; 1024];
    match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
        Ok(Ok((len, from))) => Some((buf[..len].to_vec(), from)),
        _ => None,
    }
}

/// Like [`exchange`] but parses the response and asserts it is 48 bytes.
pub async fn exchange_parsed(server: SocketAddr, payload: &[u8]) -> Option<ParsedPacket> {
    let (bytes, _) = exchange(server, payload).await?;
    assert_eq!(
        bytes.len(),
        PACKET_SIZE,
        "responses must be exactly 48 bytes"
    );
    Some(NtpPacket::parse(&bytes).expect("response must parse"))
}
