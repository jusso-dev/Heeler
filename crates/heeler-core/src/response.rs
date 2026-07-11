//! Construction of server-mode responses and Kiss-o'-Death packets.
//!
//! # Timestamp roles
//!
//! ```text
//! T1 = client transmit time   (request transmit timestamp)
//! T2 = server receive time    (captured on datagram arrival)
//! T3 = server transmit time   (captured immediately before send)
//! T4 = client receive time    (unknown to the server)
//! ```
//!
//! [`build_response`] fills everything except the transmit timestamp, which
//! the server stamps via [`finalize_transmit_timestamp`] as close to the
//! `send` syscall as practical. T2 and T3 are always separate measurements —
//! never the same captured value reused.

use crate::clock::ClockStatus;
use crate::packet::{
    KissCode, LeapIndicator, Mode, NtpPacket, NtpShortSigned, NtpShortUnsigned, ReferenceId,
    Stratum,
};
use crate::timestamp::NtpTimestamp;

/// Poll bounds applied when echoing a client's poll exponent (RFC 5905's
/// practical range: 2^4 = 16 s to 2^17 ≈ 36 h).
const MIN_POLL: i8 = 4;
const MAX_POLL: i8 = 17;

/// Static identity of this server instance, assembled from configuration
/// and the clock source at startup.
#[derive(Debug, Clone, Copy)]
pub struct ServerIdentity {
    /// Configured stratum (1-15).
    pub stratum: Stratum,
    /// Configured four-byte reference identifier.
    pub reference_id: ReferenceId,
    /// Advertised precision exponent (log2 seconds).
    pub precision: i8,
    /// Advertised root delay.
    pub root_delay: NtpShortSigned,
    /// Advertised root dispersion.
    pub root_dispersion: NtpShortUnsigned,
    /// Poll exponent used when the client's value is out of range.
    pub default_poll: i8,
    /// Leap indicator advertised while synchronised.
    pub leap: LeapIndicator,
}

/// Builds a server-mode response to a validated client request.
///
/// * the response version mirrors the (already validated) request version;
/// * the origin timestamp is a copy of the client's transmit timestamp — the
///   only client field echoed back;
/// * the receive timestamp is `receive_timestamp` (T2), captured by the
///   caller when the datagram arrived;
/// * the transmit timestamp is left zero; stamp it with
///   [`finalize_transmit_timestamp`] just before sending;
/// * when `clock_status` is unsynchronised the response carries leap
///   indicator 3 and stratum 16 regardless of configuration;
/// * `reference_timestamp` is when the clock source was last valid — never
///   the current time.
#[must_use]
pub fn build_response(
    request: &NtpPacket,
    identity: &ServerIdentity,
    clock_status: ClockStatus,
    reference_timestamp: NtpTimestamp,
    receive_timestamp: NtpTimestamp,
) -> NtpPacket {
    let (leap, stratum) = match clock_status {
        ClockStatus::Synchronised => (identity.leap, identity.stratum),
        ClockStatus::Unsynchronised => (LeapIndicator::Unsynchronised, Stratum::UNSYNCHRONISED),
    };
    NtpPacket {
        leap,
        version: request.version,
        mode: Mode::Server,
        stratum,
        poll: echo_poll(request.poll, identity.default_poll),
        precision: identity.precision,
        root_delay: identity.root_delay,
        root_dispersion: identity.root_dispersion,
        reference_id: identity.reference_id,
        reference_timestamp,
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp,
        transmit_timestamp: NtpTimestamp::ZERO,
    }
}

/// Builds a Kiss-o'-Death packet: stratum 0 with the kiss code in the
/// reference identifier. The origin timestamp still echoes the client's
/// transmit timestamp so compliant clients can match it to their request.
/// The response is exactly 48 bytes — KoD can never amplify.
#[must_use]
pub fn build_kiss_of_death(
    request: &NtpPacket,
    code: KissCode,
    receive_timestamp: NtpTimestamp,
) -> NtpPacket {
    NtpPacket {
        leap: LeapIndicator::Unsynchronised,
        version: request.version,
        mode: Mode::Server,
        stratum: Stratum::KISS_OF_DEATH,
        poll: echo_poll(request.poll, MIN_POLL),
        precision: 0,
        root_delay: NtpShortSigned::ZERO,
        root_dispersion: NtpShortUnsigned::ZERO,
        reference_id: code.reference_id(),
        reference_timestamp: NtpTimestamp::ZERO,
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp,
        transmit_timestamp: NtpTimestamp::ZERO,
    }
}

/// Stamps the transmit timestamp (T3). Call immediately before the send
/// operation so T3 reflects actual transmission as closely as user space
/// allows.
pub fn finalize_transmit_timestamp(response: &mut NtpPacket, transmit_timestamp: NtpTimestamp) {
    response.transmit_timestamp = transmit_timestamp;
}

/// Echoes the client's poll exponent when it is within the practical range,
/// otherwise substitutes the server default (itself clamped).
fn echo_poll(client_poll: i8, default_poll: i8) -> i8 {
    if (MIN_POLL..=MAX_POLL).contains(&client_poll) {
        client_poll
    } else {
        default_poll.clamp(MIN_POLL, MAX_POLL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NtpVersion, PACKET_SIZE};

    fn identity() -> ServerIdentity {
        ServerIdentity {
            stratum: Stratum::for_server(2).unwrap(),
            reference_id: ReferenceId::DEFAULT,
            precision: -20,
            root_delay: NtpShortSigned::from_millis(0).unwrap(),
            root_dispersion: NtpShortUnsigned::from_millis(5).unwrap(),
            default_poll: 6,
            leap: LeapIndicator::NoWarning,
        }
    }

    fn client_request(version: u8) -> NtpPacket {
        let mut data = [0u8; PACKET_SIZE];
        data[0] = (version << 3) | 3;
        data[2] = 6;
        data[40..48].copy_from_slice(&[0xE3, 0xB0, 0xF2, 0xAC, 0x80, 0, 0, 0]);
        NtpPacket::parse(&data).unwrap().packet
    }

    const T2: NtpTimestamp = NtpTimestamp::new(0xE3B0_F2AD, 0x1000_0000);
    const T3: NtpTimestamp = NtpTimestamp::new(0xE3B0_F2AD, 0x2000_0000);
    const REF: NtpTimestamp = NtpTimestamp::new(0xE3B0_F000, 0);

    #[test]
    fn response_semantics_synchronised() {
        let request = client_request(4);
        let mut response =
            build_response(&request, &identity(), ClockStatus::Synchronised, REF, T2);
        finalize_transmit_timestamp(&mut response, T3);

        assert_eq!(response.mode, Mode::Server);
        assert_eq!(response.version, NtpVersion::V4);
        assert_eq!(response.leap, LeapIndicator::NoWarning);
        assert_eq!(response.stratum.value(), 2);
        // Origin = client transmit (T1); the only echoed client field.
        assert_eq!(response.origin_timestamp, request.transmit_timestamp);
        // T2 and T3 are distinct measurements.
        assert_eq!(response.receive_timestamp, T2);
        assert_eq!(response.transmit_timestamp, T3);
        assert_ne!(response.receive_timestamp, response.transmit_timestamp);
        assert_eq!(response.reference_timestamp, REF);
        assert_eq!(response.reference_id, ReferenceId::DEFAULT);
    }

    #[test]
    fn response_mirrors_request_version() {
        let request = client_request(3);
        let response = build_response(&request, &identity(), ClockStatus::Synchronised, REF, T2);
        assert_eq!(response.version, NtpVersion::V3);
    }

    #[test]
    fn unsynchronised_clock_forces_alarm_and_stratum_16() {
        let request = client_request(4);
        let response = build_response(&request, &identity(), ClockStatus::Unsynchronised, REF, T2);
        assert_eq!(response.leap, LeapIndicator::Unsynchronised);
        assert_eq!(response.stratum, Stratum::UNSYNCHRONISED);
    }

    #[test]
    fn client_metadata_is_not_copied() {
        let mut data = [0u8; PACKET_SIZE];
        data[0] = (4 << 3) | 3;
        data[1] = 1; // client claims stratum 1
        data[3] = 0x80; // absurd precision
        data[4..8].copy_from_slice(&[0x7F, 0xFF, 0xFF, 0xFF]); // huge root delay
        data[12..16].copy_from_slice(b"EVIL");
        data[16..24].copy_from_slice(&[0xAA; 8]); // reference ts
        data[32..40].copy_from_slice(&[0xBB; 8]); // receive ts
        let request = NtpPacket::parse(&data).unwrap().packet;

        let response = build_response(&request, &identity(), ClockStatus::Synchronised, REF, T2);
        assert_eq!(response.stratum.value(), 2);
        assert_eq!(response.precision, -20);
        assert_eq!(response.root_delay, NtpShortSigned::ZERO);
        assert_eq!(response.reference_id, ReferenceId::DEFAULT);
        assert_eq!(response.reference_timestamp, REF);
        assert_eq!(response.receive_timestamp, T2);
    }

    #[test]
    fn poll_echo_and_clamp() {
        let mut request = client_request(4);
        request.poll = 10;
        let response = build_response(&request, &identity(), ClockStatus::Synchronised, REF, T2);
        assert_eq!(response.poll, 10);

        request.poll = -3; // out of range: use server default
        let response = build_response(&request, &identity(), ClockStatus::Synchronised, REF, T2);
        assert_eq!(response.poll, 6);

        request.poll = 100; // out of range high
        let response = build_response(&request, &identity(), ClockStatus::Synchronised, REF, T2);
        assert_eq!(response.poll, 6);
    }

    #[test]
    fn kiss_of_death_shape() {
        let request = client_request(4);
        let kod = build_kiss_of_death(&request, KissCode::Rate, T2);
        assert_eq!(kod.stratum, Stratum::KISS_OF_DEATH);
        assert_eq!(kod.mode, Mode::Server);
        assert_eq!(kod.reference_id.as_bytes(), *b"RATE");
        assert_eq!(kod.origin_timestamp, request.transmit_timestamp);
        assert_eq!(kod.leap, LeapIndicator::Unsynchronised);
        // Always exactly one base packet: no amplification.
        assert_eq!(kod.encode().len(), PACKET_SIZE);
    }
}
