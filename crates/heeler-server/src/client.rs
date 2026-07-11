//! Built-in diagnostic NTP client (`heeler query`).
//!
//! Sends a single client-mode request, records T1/T4 locally, decodes T2/T3
//! from the response, and computes the standard round-trip delay and offset:
//!
//! ```text
//! delay  = (T4 - T1) - (T3 - T2)
//! offset = ((T2 - T1) + (T3 - T4)) / 2
//! ```
//!
//! All arithmetic is signed 128-bit nanoseconds. The client only measures —
//! it never modifies the local clock.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime};

use heeler_core::packet::{
    LeapIndicator, Mode, NtpPacket, NtpShortSigned, NtpShortUnsigned, NtpVersion, ReferenceId,
    Stratum,
};
use heeler_core::timestamp::{NtpInstant, NtpTimestamp};

/// Options for a diagnostic query.
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Server, as `host`, `host:port`, `ip`, or `[v6]:port`. Port defaults
    /// to 123.
    pub server: String,
    /// NTP version to send (3 or 4).
    pub version: u8,
    /// Receive timeout.
    pub timeout: Duration,
}

/// The decoded outcome of a diagnostic query.
#[derive(Debug)]
pub struct QueryReport {
    /// Address actually queried.
    pub server: SocketAddr,
    /// T1: client transmit instant.
    pub t1: NtpInstant,
    /// T2: server receive instant (era-unfolded).
    pub t2: NtpInstant,
    /// T3: server transmit instant (era-unfolded).
    pub t3: NtpInstant,
    /// T4: client receive instant.
    pub t4: NtpInstant,
    /// Round-trip delay in nanoseconds (signed; asymmetric paths can
    /// produce small negatives).
    pub delay_nanos: i128,
    /// Clock offset (server minus client) in nanoseconds.
    pub offset_nanos: i128,
    /// The raw response packet.
    pub response: NtpPacket,
    /// Whether the response origin timestamp matched our transmit
    /// timestamp (a mismatch suggests a broken or off-path server).
    pub origin_matched: bool,
}

/// Errors from the diagnostic client.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The server name did not resolve.
    #[error("cannot resolve {0:?}")]
    Resolve(String),
    /// Socket setup or I/O failed.
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
    /// No response arrived within the timeout.
    #[error("timed out after {0:?} waiting for a response")]
    Timeout(Duration),
    /// The response was not a parseable NTP packet.
    #[error("malformed response: {0}")]
    Malformed(#[from] heeler_core::error::ParseError),
    /// The response was not a server-mode packet.
    #[error("unexpected response mode {0}")]
    UnexpectedMode(Mode),
    /// The local clock could not be read or represented.
    #[error("local clock error: {0}")]
    Clock(#[from] heeler_core::error::TimestampError),
}

/// Performs one query.
pub fn query(options: &QueryOptions) -> Result<QueryReport, QueryError> {
    let server = resolve(&options.server)?;
    let bind_addr: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap_or_else(|_| unreachable!())
    } else {
        "[::]:0".parse().unwrap_or_else(|_| unreachable!())
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(options.timeout))?;
    socket.connect(server)?;

    // T1, also placed in the transmit timestamp so the server echoes it.
    let t1 = NtpInstant::from_system_time(SystemTime::now());
    let t1_wire = t1.to_timestamp()?;
    let request = NtpPacket {
        leap: LeapIndicator::NoWarning,
        version: NtpVersion::from_bits(options.version),
        mode: Mode::Client,
        stratum: Stratum::from_raw(0),
        poll: 6,
        precision: -20,
        root_delay: NtpShortSigned::ZERO,
        root_dispersion: NtpShortUnsigned::ZERO,
        reference_id: ReferenceId::from_bytes([0; 4]),
        reference_timestamp: NtpTimestamp::ZERO,
        origin_timestamp: NtpTimestamp::ZERO,
        receive_timestamp: NtpTimestamp::ZERO,
        transmit_timestamp: t1_wire,
    };
    socket.send(&request.encode())?;

    let mut buf = [0u8; 512];
    let len = match socket.recv(&mut buf) {
        Ok(len) => len,
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut =>
        {
            return Err(QueryError::Timeout(options.timeout));
        }
        Err(error) => return Err(error.into()),
    };
    // T4 immediately after receipt.
    let t4 = NtpInstant::from_system_time(SystemTime::now());

    let parsed = NtpPacket::parse(&buf[..len])?;
    let response = parsed.packet;
    if response.mode != Mode::Server {
        return Err(QueryError::UnexpectedMode(response.mode));
    }
    let origin_matched = response.origin_timestamp == t1_wire;

    // Era-unfold the server timestamps against our local clock as pivot.
    let t2 = response.receive_timestamp.unfold(t1);
    let t3 = response.transmit_timestamp.unfold(t1);

    // delay = (T4 - T1) - (T3 - T2); offset = ((T2 - T1) + (T3 - T4)) / 2
    let delay_nanos = t4.nanos_since(t1) - t3.nanos_since(t2);
    let offset_nanos = (t2.nanos_since(t1) + t3.nanos_since(t4)) / 2;

    Ok(QueryReport {
        server,
        t1,
        t2,
        t3,
        t4,
        delay_nanos,
        offset_nanos,
        response,
        origin_matched,
    })
}

fn resolve(server: &str) -> Result<SocketAddr, QueryError> {
    // Accept an explicit port ("host:123", "[::1]:123"); otherwise default
    // to port 123.
    let with_default_port;
    let candidate = if server.parse::<SocketAddr>().is_ok() || has_port(server) {
        server
    } else {
        with_default_port = format!("{server}:123");
        &with_default_port
    };
    candidate
        .to_socket_addrs()
        .map_err(|_| QueryError::Resolve(server.to_owned()))?
        .next()
        .ok_or_else(|| QueryError::Resolve(server.to_owned()))
}

fn has_port(server: &str) -> bool {
    if let Some(rest) = server.strip_prefix('[') {
        // Bracketed IPv6: a port follows "]:".
        return rest.contains("]:");
    }
    // Exactly one colon and not a bare IPv6 address → host:port.
    server.matches(':').count() == 1
}

/// Formats a report for terminal display.
#[must_use]
pub fn format_report(report: &QueryReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let r = &report.response;
    let _ = writeln!(out, "server            {}", report.server);
    let _ = writeln!(out, "leap              {}", r.leap);
    let _ = writeln!(out, "version           {}", r.version);
    let _ = writeln!(out, "mode              {}", r.mode);
    if r.stratum.is_kiss_of_death() {
        let _ = writeln!(
            out,
            "stratum           0 (Kiss-o'-Death, code {})",
            r.reference_id
        );
    } else {
        let _ = writeln!(out, "stratum           {}", r.stratum);
    }
    let _ = writeln!(out, "poll              {}", r.poll);
    let _ = writeln!(out, "precision         {} (2^{} s)", r.precision, r.precision);
    let _ = writeln!(
        out,
        "root delay        {:.6} s",
        r.root_delay.to_seconds_f64()
    );
    let _ = writeln!(
        out,
        "root dispersion   {:.6} s",
        r.root_dispersion.to_seconds_f64()
    );
    let _ = writeln!(out, "reference id      {}", r.reference_id);
    let _ = writeln!(out, "reference ts      {}", r.reference_timestamp);
    let _ = writeln!(out);
    let _ = writeln!(out, "T1 (client tx)    {}", crate::inspect::format_instant(report.t1));
    let _ = writeln!(out, "T2 (server rx)    {}", crate::inspect::format_instant(report.t2));
    let _ = writeln!(out, "T3 (server tx)    {}", crate::inspect::format_instant(report.t3));
    let _ = writeln!(out, "T4 (client rx)    {}", crate::inspect::format_instant(report.t4));
    let _ = writeln!(
        out,
        "raw T2/T3         {} / {}",
        r.receive_timestamp, r.transmit_timestamp
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "round-trip delay  {:+.6} ms",
        report.delay_nanos as f64 / 1e6
    );
    let _ = writeln!(
        out,
        "clock offset      {:+.6} ms",
        report.offset_nanos as f64 / 1e6
    );
    if !report.origin_matched {
        let _ = writeln!(
            out,
            "warning: response origin timestamp did not echo our request"
        );
    }
    let _ = write!(
        out,
        "note: user-space timestamps; accuracy is bounded by scheduling and \
         network asymmetry"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_forms() {
        assert_eq!(
            resolve("127.0.0.1").unwrap(),
            "127.0.0.1:123".parse().unwrap()
        );
        assert_eq!(
            resolve("127.0.0.1:1234").unwrap(),
            "127.0.0.1:1234".parse().unwrap()
        );
        assert_eq!(resolve("::1").unwrap(), "[::1]:123".parse().unwrap());
        assert_eq!(
            resolve("[::1]:1234").unwrap(),
            "[::1]:1234".parse().unwrap()
        );
        assert!(resolve("").is_err());
    }
}
