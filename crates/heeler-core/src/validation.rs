//! Request-acceptance policy for inbound packets.
//!
//! The parser accepts anything structurally sound; this module decides
//! whether a parsed packet is a client request Heeler is willing to answer.
//! The server layer maps each [`RequestRejection`] to a silent drop, a
//! counter, or (for policy denials) a Kiss-o'-Death.

use crate::error::RequestRejection;
use crate::packet::{Mode, ParsedPacket};

/// Policy applied to every parsed inbound packet.
#[derive(Debug, Clone)]
pub struct ValidationPolicy {
    /// NTP versions this instance answers (subset of 1-7; default `[3, 4]`).
    pub supported_versions: Vec<u8>,
    /// Reject requests whose transmit timestamp is zero. Off by default for
    /// compatibility: some SNTP clients legitimately send zero fields.
    pub require_nonzero_transmit_timestamp: bool,
    /// Accept datagrams with bytes after the 48-byte base packet (extension
    /// fields / MACs Heeler does not interpret). Off by default.
    pub allow_trailing_data: bool,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            supported_versions: vec![3, 4],
            require_nonzero_transmit_timestamp: false,
            allow_trailing_data: false,
        }
    }
}

impl ValidationPolicy {
    /// Validates a parsed packet as an answerable client request.
    ///
    /// Checks, in order: trailing data policy, mode (only mode 3 client
    /// requests are ever answered — control, private, broadcast, server,
    /// and symmetric packets are refused to avoid reflection behaviour),
    /// version policy, and the transmit-timestamp policy.
    pub fn validate(&self, parsed: &ParsedPacket) -> Result<(), RequestRejection> {
        if parsed.trailing_bytes > 0 && !self.allow_trailing_data {
            return Err(RequestRejection::TrailingData {
                trailing: parsed.trailing_bytes,
            });
        }
        let packet = &parsed.packet;
        if packet.mode != Mode::Client {
            return Err(RequestRejection::UnsupportedMode(packet.mode));
        }
        let version = packet.version.to_bits();
        if !self.supported_versions.contains(&version) {
            return Err(RequestRejection::UnsupportedVersion(version));
        }
        if self.require_nonzero_transmit_timestamp && packet.transmit_timestamp.is_zero() {
            return Err(RequestRejection::ZeroTransmitTimestamp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NtpPacket, PACKET_SIZE};

    fn client_request(version: u8, mode: u8) -> Vec<u8> {
        let mut data = vec![0u8; PACKET_SIZE];
        data[0] = (version << 3) | mode;
        data[40] = 0xE3; // non-zero transmit timestamp
        data
    }

    #[test]
    fn accepts_v3_and_v4_client_requests() {
        let policy = ValidationPolicy::default();
        for version in [3u8, 4] {
            let parsed = NtpPacket::parse(&client_request(version, 3)).unwrap();
            assert_eq!(policy.validate(&parsed), Ok(()));
        }
    }

    #[test]
    fn rejects_unsupported_versions() {
        let policy = ValidationPolicy::default();
        for version in [0u8, 1, 2, 5, 6, 7] {
            let parsed = NtpPacket::parse(&client_request(version, 3)).unwrap();
            assert_eq!(
                policy.validate(&parsed),
                Err(RequestRejection::UnsupportedVersion(version))
            );
        }
    }

    #[test]
    fn rejects_all_non_client_modes() {
        let policy = ValidationPolicy::default();
        for mode in [0u8, 1, 2, 4, 5, 6, 7] {
            let parsed = NtpPacket::parse(&client_request(4, mode)).unwrap();
            assert!(matches!(
                policy.validate(&parsed),
                Err(RequestRejection::UnsupportedMode(_))
            ));
        }
    }

    #[test]
    fn mode_check_precedes_version_check() {
        // A control packet with a bad version is reported as bad mode:
        // mode 6/7 traffic must never be treated as a versioned time query.
        let policy = ValidationPolicy::default();
        let parsed = NtpPacket::parse(&client_request(2, 6)).unwrap();
        assert!(matches!(
            policy.validate(&parsed),
            Err(RequestRejection::UnsupportedMode(Mode::Control))
        ));
    }

    #[test]
    fn trailing_data_policy() {
        let mut data = client_request(4, 3);
        data.extend_from_slice(&[0u8; 4]);
        let parsed = NtpPacket::parse(&data).unwrap();

        let strict = ValidationPolicy::default();
        assert_eq!(
            strict.validate(&parsed),
            Err(RequestRejection::TrailingData { trailing: 4 })
        );

        let lenient = ValidationPolicy {
            allow_trailing_data: true,
            ..ValidationPolicy::default()
        };
        assert_eq!(lenient.validate(&parsed), Ok(()));
    }

    #[test]
    fn zero_transmit_timestamp_policy() {
        let mut data = client_request(4, 3);
        data[40] = 0; // zero the transmit timestamp again
        let parsed = NtpPacket::parse(&data).unwrap();

        let lenient = ValidationPolicy::default();
        assert_eq!(lenient.validate(&parsed), Ok(()));

        let strict = ValidationPolicy {
            require_nonzero_transmit_timestamp: true,
            ..ValidationPolicy::default()
        };
        assert_eq!(
            strict.validate(&parsed),
            Err(RequestRejection::ZeroTransmitTimestamp)
        );
    }
}
