//! Counters and an optional Prometheus text endpoint.
//!
//! All metrics are plain atomics with **no per-client labels** — labelling by
//! source address would let an attacker inflate metric cardinality. The
//! HTTP listener is a deliberately tiny, self-contained responder (no HTTP
//! framework): it answers `GET /metrics` with the text exposition format and
//! everything else with 404, and it binds to loopback by default.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Histogram buckets for response build duration, in nanoseconds.
const BUILD_BUCKETS_NANOS: [u64; 6] = [1_000, 5_000, 10_000, 50_000, 100_000, 1_000_000];

/// All server counters. Cheap to update from the packet path.
pub struct Metrics {
    started: Instant,
    /// Datagrams received (any outcome).
    pub requests_total: AtomicU64,
    /// Responses sent (including Kiss-o'-Death).
    pub responses_total: AtomicU64,
    /// Datagrams dropped for any reason.
    pub packets_dropped_total: AtomicU64,
    /// Datagrams that were malformed (too short, oversized, trailing data).
    pub malformed_packets_total: AtomicU64,
    /// Well-formed packets with an unserved version.
    pub unsupported_version_total: AtomicU64,
    /// Well-formed packets with a non-client mode.
    pub unsupported_mode_total: AtomicU64,
    /// Requests refused by the rate limiter.
    pub rate_limited_total: AtomicU64,
    /// Requests refused by access control.
    pub access_denied_total: AtomicU64,
    /// Kiss-o'-Death responses sent.
    pub kod_sent_total: AtomicU64,
    /// Socket receive/send errors.
    pub socket_errors_total: AtomicU64,
    /// Clock reading failures.
    pub clock_errors_total: AtomicU64,
    /// Detected wall-clock jumps.
    pub clock_jumps_total: AtomicU64,
    /// 1 while the clock source is synchronised, else 0.
    pub clock_synchronised: AtomicU64,
    /// Currently tracked rate-limiter entries.
    pub active_rate_limit_entries: AtomicU64,
    build_bucket_counts: [AtomicU64; 6],
    build_count: AtomicU64,
    build_sum_nanos: AtomicU64,
}

impl Metrics {
    /// Creates a zeroed metrics set; `clock_synchronised` starts at 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            requests_total: AtomicU64::new(0),
            responses_total: AtomicU64::new(0),
            packets_dropped_total: AtomicU64::new(0),
            malformed_packets_total: AtomicU64::new(0),
            unsupported_version_total: AtomicU64::new(0),
            unsupported_mode_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            access_denied_total: AtomicU64::new(0),
            kod_sent_total: AtomicU64::new(0),
            socket_errors_total: AtomicU64::new(0),
            clock_errors_total: AtomicU64::new(0),
            clock_jumps_total: AtomicU64::new(0),
            clock_synchronised: AtomicU64::new(1),
            active_rate_limit_entries: AtomicU64::new(0),
            build_bucket_counts: Default::default(),
            build_count: AtomicU64::new(0),
            build_sum_nanos: AtomicU64::new(0),
        }
    }

    /// Records one response build duration in the histogram.
    pub fn observe_build_duration(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        for (bucket, le) in self.build_bucket_counts.iter().zip(BUILD_BUCKETS_NANOS) {
            if nanos <= le {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.build_count.fetch_add(1, Ordering::Relaxed);
        self.build_sum_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    /// Renders the Prometheus text exposition format.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(2048);
        let counters: [(&str, &str, u64); 13] = [
            (
                "heeler_requests_total",
                "Datagrams received",
                self.requests_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_responses_total",
                "Responses sent",
                self.responses_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_packets_dropped_total",
                "Datagrams dropped",
                self.packets_dropped_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_malformed_packets_total",
                "Malformed datagrams",
                self.malformed_packets_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_unsupported_version_total",
                "Unsupported NTP version requests",
                self.unsupported_version_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_unsupported_mode_total",
                "Non-client-mode packets",
                self.unsupported_mode_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_rate_limited_total",
                "Rate-limited requests",
                self.rate_limited_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_access_denied_total",
                "Access-denied requests",
                self.access_denied_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_kod_sent_total",
                "Kiss-o'-Death responses sent",
                self.kod_sent_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_socket_errors_total",
                "Socket errors",
                self.socket_errors_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_clock_errors_total",
                "Clock read failures",
                self.clock_errors_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_clock_jumps_total",
                "Detected wall-clock jumps",
                self.clock_jumps_total.load(Ordering::Relaxed),
            ),
            (
                "heeler_active_rate_limit_entries",
                "Tracked rate-limiter entries",
                self.active_rate_limit_entries.load(Ordering::Relaxed),
            ),
        ];
        for (name, help, value) in counters {
            let kind = if name.ends_with("_total") {
                "counter"
            } else {
                "gauge"
            };
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {kind}");
            let _ = writeln!(out, "{name} {value}");
        }
        let _ = writeln!(
            out,
            "# HELP heeler_clock_synchronised 1 while the clock source is synchronised"
        );
        let _ = writeln!(out, "# TYPE heeler_clock_synchronised gauge");
        let _ = writeln!(
            out,
            "heeler_clock_synchronised {}",
            self.clock_synchronised.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP heeler_uptime_seconds Seconds since the server started"
        );
        let _ = writeln!(out, "# TYPE heeler_uptime_seconds gauge");
        let _ = writeln!(
            out,
            "heeler_uptime_seconds {}",
            self.started.elapsed().as_secs()
        );

        let _ = writeln!(
            out,
            "# HELP heeler_response_build_duration_seconds Time to build one response"
        );
        let _ = writeln!(
            out,
            "# TYPE heeler_response_build_duration_seconds histogram"
        );
        for (bucket, le) in self.build_bucket_counts.iter().zip(BUILD_BUCKETS_NANOS) {
            let _ = writeln!(
                out,
                "heeler_response_build_duration_seconds_bucket{{le=\"{}\"}} {}",
                le as f64 / 1e9,
                bucket.load(Ordering::Relaxed)
            );
        }
        let count = self.build_count.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "heeler_response_build_duration_seconds_bucket{{le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(
            out,
            "heeler_response_build_duration_seconds_sum {}",
            self.build_sum_nanos.load(Ordering::Relaxed) as f64 / 1e9
        );
        let _ = writeln!(out, "heeler_response_build_duration_seconds_count {count}");
        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Serves `GET /metrics` until `shutdown` flips to true. Reads at most 4 KiB
/// of request and never echoes request content back.
pub async fn serve_metrics(
    listener: TcpListener,
    metrics: std::sync::Arc<Metrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let (mut stream, peer) = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
                continue;
            }
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::warn!(%error, "metrics accept failed");
                    continue;
                }
            },
        };
        tracing::trace!(%peer, "metrics connection");
        let metrics = metrics.clone();
        // One short-lived task per metrics scrape; scrapes come from the
        // operator's collector, not the untrusted packet path.
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            let n = match read {
                Ok(Ok(n)) => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let response = if request.starts_with("GET /metrics ") {
                let body = metrics.render();
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    .to_owned()
            };
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_all_series() {
        let metrics = Metrics::new();
        metrics.requests_total.fetch_add(3, Ordering::Relaxed);
        metrics.observe_build_duration(Duration::from_nanos(7_000));
        let text = metrics.render();
        for name in [
            "heeler_requests_total 3",
            "heeler_responses_total 0",
            "heeler_packets_dropped_total",
            "heeler_malformed_packets_total",
            "heeler_unsupported_version_total",
            "heeler_unsupported_mode_total",
            "heeler_rate_limited_total",
            "heeler_access_denied_total",
            "heeler_socket_errors_total",
            "heeler_clock_jumps_total",
            "heeler_clock_synchronised 1",
            "heeler_active_rate_limit_entries",
            "heeler_uptime_seconds",
            "heeler_response_build_duration_seconds_count 1",
        ] {
            assert!(text.contains(name), "missing series {name}\n{text}");
        }
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let metrics = Metrics::new();
        metrics.observe_build_duration(Duration::from_nanos(500));
        metrics.observe_build_duration(Duration::from_nanos(20_000));
        metrics.observe_build_duration(Duration::from_secs(1));
        let text = metrics.render();
        assert!(text.contains("le=\"0.000001\"} 1"));
        assert!(text.contains("le=\"0.00005\"} 2"));
        assert!(text.contains("le=\"+Inf\"} 3"));
    }
}
