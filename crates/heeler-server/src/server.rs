//! The UDP server runtime.
//!
//! One logical receive loop per bound socket; every request is processed
//! inline (parse → validate → respond is allocation-free and cheap), so no
//! per-packet tasks are ever spawned. A single housekeeping task drives
//! clock-jump detection and rate-limiter expiry.
//!
//! Datagram pipeline (see the architecture section of the README):
//! size validation → access control → rate limiter → packet parser →
//! protocol validation → clock source → response builder → encoder → send.
//! The receive timestamp (T2) is captured immediately after `recv_from`
//! returns, before any validation; the transmit timestamp (T3) is captured
//! immediately before `send_to`.

use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use heeler_core::clock::{ClockSource, ClockStatus, SystemClockSource};
use heeler_core::error::RequestRejection;
use heeler_core::packet::{KissCode, NtpPacket};
use heeler_core::response::{build_kiss_of_death, build_response, finalize_transmit_timestamp};
use heeler_core::timestamp::NtpTimestamp;
use heeler_core::validation::ValidationPolicy;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::access::{AccessControl, AccessDecision};
use crate::config::{ServerSection, ValidatedConfig};
use crate::metrics::Metrics;
use crate::rate_limit::{RateDecision, RateLimitSettings, RateLimiter};

/// Everything the packet path needs, shared across receive loops.
pub struct ServerState {
    /// Static response identity (stratum, refid, root fields, precision).
    pub identity: heeler_core::response::ServerIdentity,
    /// The active clock source.
    pub clock: Arc<dyn ClockSource>,
    /// The system clock, when it is the active source (for jump checks).
    pub system_clock: Option<Arc<SystemClockSource>>,
    /// Compiled access rules.
    pub access: AccessControl,
    /// The rate limiter.
    pub limiter: RateLimiter,
    /// Shared counters.
    pub metrics: Arc<Metrics>,
    /// Packet validation policy.
    pub policy: ValidationPolicy,
    /// Largest accepted datagram.
    pub max_packet_size: usize,
    /// Send a RATE KoD to per-client rate-limited requests.
    pub send_kod_on_rate_limit: bool,
    /// Send a DENY KoD to access-denied requests.
    pub send_kod_on_policy_deny: bool,
}

impl ServerState {
    /// Assembles the runtime state from a validated configuration and an
    /// already-constructed clock source.
    pub fn new(
        validated: &ValidatedConfig,
        clock: Arc<dyn ClockSource>,
        system_clock: Option<Arc<SystemClockSource>>,
    ) -> Self {
        let mut identity = validated.identity;
        if !validated.precision_configured {
            identity.precision = clock.estimated_precision().exponent();
        }
        let rate = &validated.config.rate_limit;
        Self {
            identity,
            clock,
            system_clock,
            access: validated.access.clone(),
            limiter: RateLimiter::new(
                RateLimitSettings {
                    enabled: rate.enabled,
                    requests_per_second: rate.requests_per_second,
                    burst: rate.burst,
                    global_requests_per_second: rate.global_requests_per_second,
                    global_burst: rate.global_burst,
                    client_entry_ttl: Duration::from_secs(rate.client_entry_ttl_seconds),
                    max_client_entries: rate.max_client_entries,
                },
                Instant::now(),
            ),
            metrics: Arc::new(Metrics::new()),
            policy: validated.validation_policy.clone(),
            max_packet_size: validated.config.server.max_packet_size,
            send_kod_on_rate_limit: validated.config.protocol.send_kod_on_rate_limit,
            send_kod_on_policy_deny: validated.config.protocol.send_kod_on_policy_deny,
        }
    }

    /// Processes one received datagram. `receive_timestamp` (T2) must be
    /// captured by the caller immediately after `recv_from` returns.
    async fn handle_datagram(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        source: SocketAddr,
        receive_timestamp: NtpTimestamp,
    ) {
        let metrics = &self.metrics;
        metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        // 1. Size validation. `data` can never exceed max_packet_size + 1
        //    (the buffer size); a full buffer means a truncated datagram.
        if data.len() > self.max_packet_size {
            metrics
                .malformed_packets_total
                .fetch_add(1, Ordering::Relaxed);
            metrics
                .packets_dropped_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(%source, len = data.len(), "dropped oversized datagram");
            return;
        }

        // 2. Access control.
        if self.access.evaluate(source.ip()) == AccessDecision::Denied {
            metrics.access_denied_total.fetch_add(1, Ordering::Relaxed);
            if self.send_kod_on_policy_deny {
                self.send_kod(socket, data, source, KissCode::Deny, receive_timestamp)
                    .await;
            } else {
                metrics
                    .packets_dropped_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            tracing::debug!(%source, "access denied");
            return;
        }

        // 3. Rate limiting (monotonic time only).
        match self.limiter.check(source.ip(), Instant::now()) {
            RateDecision::Allowed => {}
            RateDecision::LimitedPerClient { send_kod } => {
                metrics.rate_limited_total.fetch_add(1, Ordering::Relaxed);
                if send_kod && self.send_kod_on_rate_limit {
                    self.send_kod(socket, data, source, KissCode::Rate, receive_timestamp)
                        .await;
                } else {
                    metrics
                        .packets_dropped_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            RateDecision::LimitedGlobal | RateDecision::TableFull => {
                // Never answered: a KoD per packet under global overload
                // would reflect a flood 1:1.
                metrics.rate_limited_total.fetch_add(1, Ordering::Relaxed);
                metrics
                    .packets_dropped_total
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        // 4. Parse.
        let build_start = Instant::now();
        let parsed = match NtpPacket::parse(data) {
            Ok(parsed) => parsed,
            Err(error) => {
                metrics
                    .malformed_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                metrics
                    .packets_dropped_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::trace!(%source, %error, "dropped malformed datagram");
                return;
            }
        };

        // 5. Protocol validation.
        if let Err(rejection) = self.policy.validate(&parsed) {
            match rejection {
                RequestRejection::UnsupportedVersion(_) => {
                    metrics
                        .unsupported_version_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                RequestRejection::UnsupportedMode(_) => {
                    metrics
                        .unsupported_mode_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                RequestRejection::TrailingData { .. } | RequestRejection::ZeroTransmitTimestamp => {
                    metrics
                        .malformed_packets_total
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            metrics
                .packets_dropped_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(%source, %rejection, "dropped rejected packet");
            return;
        }

        // 6-8. Clock source, response builder, encoder.
        let status = self.clock.status();
        let reference_timestamp = self
            .clock
            .reference_timestamp()
            .unwrap_or(NtpTimestamp::ZERO);
        let mut response = build_response(
            &parsed.packet,
            &self.identity,
            status,
            reference_timestamp,
            receive_timestamp,
        );
        metrics.observe_build_duration(build_start.elapsed());

        // 9. Stamp T3 as late as practical and send. T3 is a fresh clock
        //    reading, never the T2 value reused.
        let transmit = match self.clock.now() {
            Ok(reading) => reading.timestamp,
            Err(error) => {
                metrics.clock_errors_total.fetch_add(1, Ordering::Relaxed);
                metrics
                    .packets_dropped_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, "clock read failed; dropping request");
                return;
            }
        };
        finalize_transmit_timestamp(&mut response, transmit);
        match socket.send_to(&response.encode(), source).await {
            Ok(_) => {
                metrics.responses_total.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(%source, "sent response");
            }
            Err(error) => {
                metrics.socket_errors_total.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%source, %error, "send failed");
            }
        }
    }

    /// Sends a Kiss-o'-Death if the offending datagram itself parses and
    /// validates as a client request; otherwise drops silently. The KoD is
    /// exactly 48 bytes, so it can never amplify.
    async fn send_kod(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        source: SocketAddr,
        code: KissCode,
        receive_timestamp: NtpTimestamp,
    ) {
        let Ok(parsed) = NtpPacket::parse(data) else {
            self.metrics
                .packets_dropped_total
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if self.policy.validate(&parsed).is_err() {
            self.metrics
                .packets_dropped_total
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut kod = build_kiss_of_death(&parsed.packet, code, receive_timestamp);
        let transmit = match self.clock.now() {
            Ok(reading) => reading.timestamp,
            Err(_) => NtpTimestamp::ZERO,
        };
        finalize_transmit_timestamp(&mut kod, transmit);
        match socket.send_to(&kod.encode(), source).await {
            Ok(_) => {
                self.metrics.kod_sent_total.fetch_add(1, Ordering::Relaxed);
                self.metrics.responses_total.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.metrics
                    .socket_errors_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Binds all configured addresses with the configured socket options,
/// returning standard (blocking) sockets ready to hand to the runtime.
/// Binding happens before privilege drop; the sockets stay usable after.
pub fn bind_sockets(section: &ServerSection) -> std::io::Result<Vec<StdUdpSocket>> {
    section
        .bind
        .iter()
        .map(|addr| bind_socket(*addr, section))
        .collect()
}

fn bind_socket(addr: SocketAddr, section: &ServerSection) -> std::io::Result<StdUdpSocket> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        // Keep address families separate: v4 traffic is served by the v4
        // socket. Rules and logs then always see native addresses.
        socket.set_only_v6(true)?;
    }
    if section.reuse_addr {
        socket.set_reuse_address(true)?;
    }
    if section.recv_buffer_bytes > 0 {
        socket.set_recv_buffer_size(section.recv_buffer_bytes)?;
    }
    if section.send_buffer_bytes > 0 {
        socket.set_send_buffer_size(section.send_buffer_bytes)?;
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Runs the server until `shutdown` flips to true: one receive loop per
/// socket plus one housekeeping task. Returns once all loops have stopped.
pub async fn run_server(
    state: Arc<ServerState>,
    sockets: Vec<StdUdpSocket>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut tasks = Vec::with_capacity(sockets.len() + 1);
    for socket in sockets {
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;
        let local = socket.local_addr()?;
        tracing::info!(%local, "listening");
        tasks.push(tokio::spawn(recv_loop(
            Arc::new(socket),
            state.clone(),
            shutdown.clone(),
        )));
    }
    tasks.push(tokio::spawn(housekeeping_loop(state, shutdown)));
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

async fn recv_loop(
    socket: Arc<UdpSocket>,
    state: Arc<ServerState>,
    mut shutdown: watch::Receiver<bool>,
) {
    // One extra byte so a datagram larger than max_packet_size is
    // detectable (recv_from truncates). Allocated once, never per packet,
    // and never sized from untrusted input.
    let mut buf = vec![0u8; state.max_packet_size + 1];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            received = socket.recv_from(&mut buf) => {
                match received {
                    Ok((len, source)) => {
                        // Capture T2 immediately, before any validation.
                        let receive_timestamp = match state.clock.now() {
                            Ok(reading) => reading.timestamp,
                            Err(error) => {
                                state.metrics.clock_errors_total.fetch_add(1, Ordering::Relaxed);
                                state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                                state.metrics.packets_dropped_total.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(%error, "clock read failed on receive");
                                continue;
                            }
                        };
                        state
                            .handle_datagram(&socket, &buf[..len], source, receive_timestamp)
                            .await;
                    }
                    Err(error) => {
                        state.metrics.socket_errors_total.fetch_add(1, Ordering::Relaxed);
                        // Transient per-packet errors (e.g. ICMP-induced
                        // ECONNREFUSED on some platforms) are not fatal.
                        tracing::debug!(%error, "recv error");
                    }
                }
            }
        }
    }
}

/// Single housekeeping task: clock-jump detection every second, limiter
/// sweep every 30 seconds, gauge refresh every second.
async fn housekeeping_loop(state: Arc<ServerState>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticks: u64 = 0;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                ticks += 1;
                if let Some(system_clock) = &state.system_clock {
                    if let Some(jump) = system_clock.check_jump() {
                        state.metrics.clock_jumps_total.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            drift_ms = jump.drift_nanos as f64 / 1e6,
                            marked_unsynchronised = jump.marked_unsynchronised,
                            "wall clock jumped relative to the monotonic clock"
                        );
                    }
                }
                let synchronised = state.clock.status() == ClockStatus::Synchronised;
                state
                    .metrics
                    .clock_synchronised
                    .store(u64::from(synchronised), Ordering::Relaxed);
                state.metrics.active_rate_limit_entries.store(
                    state.limiter.active_entries() as u64,
                    Ordering::Relaxed,
                );
                if ticks % 30 == 0 {
                    state.limiter.sweep(Instant::now());
                }
            }
        }
    }
}
