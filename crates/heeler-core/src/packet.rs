//! Parsing and encoding of the 48-byte base NTP packet.
//!
//! Every field is read and written at an explicitly named byte offset with
//! explicit big-endian conversion. No packed structs, no transmutes, no
//! reinterpretation of byte buffers.
//!
//! ```text
//! Byte 0      LI (2 bits) | VN (3 bits) | Mode (3 bits)
//! Byte 1      Stratum
//! Byte 2      Poll (signed log2 seconds)
//! Byte 3      Precision (signed log2 seconds)
//! Bytes 4-7   Root Delay        (signed 16.16 fixed point)
//! Bytes 8-11  Root Dispersion   (unsigned 16.16 fixed point)
//! Bytes 12-15 Reference Identifier
//! Bytes 16-23 Reference Timestamp
//! Bytes 24-31 Origin Timestamp
//! Bytes 32-39 Receive Timestamp
//! Bytes 40-47 Transmit Timestamp
//! ```

use crate::error::{ConfigError, ParseError};
use crate::timestamp::NtpTimestamp;

/// Size of the base NTP packet in bytes.
pub const PACKET_SIZE: usize = 48;

// Named field offsets into the 48-byte base packet.
const OFFSET_FLAGS: usize = 0;
const OFFSET_STRATUM: usize = 1;
const OFFSET_POLL: usize = 2;
const OFFSET_PRECISION: usize = 3;
const OFFSET_ROOT_DELAY: usize = 4;
const OFFSET_ROOT_DISPERSION: usize = 8;
const OFFSET_REFERENCE_ID: usize = 12;
const OFFSET_REFERENCE_TS: usize = 16;
const OFFSET_ORIGIN_TS: usize = 24;
const OFFSET_RECEIVE_TS: usize = 32;
const OFFSET_TRANSMIT_TS: usize = 40;

/// Leap indicator: the top two bits of byte 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapIndicator {
    /// 0 — no warning.
    NoWarning,
    /// 1 — the last minute of the current day has 61 seconds.
    LastMinute61,
    /// 2 — the last minute of the current day has 59 seconds.
    LastMinute59,
    /// 3 — alarm condition: the clock is unsynchronised.
    Unsynchronised,
}

impl LeapIndicator {
    /// Decodes from the low two bits of `bits`. Total: all values map.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::NoWarning,
            1 => Self::LastMinute61,
            2 => Self::LastMinute59,
            _ => Self::Unsynchronised,
        }
    }

    /// The two-bit wire value.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::NoWarning => 0,
            Self::LastMinute61 => 1,
            Self::LastMinute59 => 2,
            Self::Unsynchronised => 3,
        }
    }

    /// Builds a leap indicator from a configuration value 0-3.
    pub const fn from_config(value: u8) -> Result<Self, ConfigError> {
        if value <= 3 {
            Ok(Self::from_bits(value))
        } else {
            Err(ConfigError::InvalidLeapIndicator(value))
        }
    }
}

impl std::fmt::Display for LeapIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NoWarning => "no warning",
            Self::LastMinute61 => "last minute has 61 seconds",
            Self::LastMinute59 => "last minute has 59 seconds",
            Self::Unsynchronised => "unsynchronised",
        };
        write!(f, "{} ({text})", self.to_bits())
    }
}

/// NTP version number: the three VN bits of byte 0.
///
/// The raw three-bit value (0-7) is preserved; whether a version is *served*
/// is a policy decision made by the validation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NtpVersion(u8);

impl NtpVersion {
    /// NTP version 3 (RFC 1305).
    pub const V3: Self = Self(3);
    /// NTP version 4 (RFC 5905).
    pub const V4: Self = Self(4);

    /// Decodes from the three VN bits. Values are masked to 0-7.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & 0b111)
    }

    /// The three-bit wire value.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        self.0
    }
}

impl std::fmt::Display for NtpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Association mode: the low three bits of byte 0. Total over all values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// 0 — reserved.
    Reserved,
    /// 1 — symmetric active.
    SymmetricActive,
    /// 2 — symmetric passive.
    SymmetricPassive,
    /// 3 — client request.
    Client,
    /// 4 — server response.
    Server,
    /// 5 — broadcast.
    Broadcast,
    /// 6 — NTP control message (never answered by Heeler).
    Control,
    /// 7 — reserved for private use (never answered by Heeler).
    Private,
}

impl Mode {
    /// Decodes from the low three bits of `bits`. Total: all values map.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b111 {
            0 => Self::Reserved,
            1 => Self::SymmetricActive,
            2 => Self::SymmetricPassive,
            3 => Self::Client,
            4 => Self::Server,
            5 => Self::Broadcast,
            6 => Self::Control,
            _ => Self::Private,
        }
    }

    /// The three-bit wire value.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::SymmetricActive => 1,
            Self::SymmetricPassive => 2,
            Self::Client => 3,
            Self::Server => 4,
            Self::Broadcast => 5,
            Self::Control => 6,
            Self::Private => 7,
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Reserved => "reserved",
            Self::SymmetricActive => "symmetric active",
            Self::SymmetricPassive => "symmetric passive",
            Self::Client => "client",
            Self::Server => "server",
            Self::Broadcast => "broadcast",
            Self::Control => "control",
            Self::Private => "private",
        };
        write!(f, "{} ({text})", self.to_bits())
    }
}

/// Stratum: distance from a reference clock, byte 1 of the packet.
///
/// * 0 — Kiss-o'-Death (in server packets) or "unspecified";
/// * 1 — primary server attached to a reference clock;
/// * 2-15 — secondary servers;
/// * 16 — unsynchronised;
/// * 17-255 — reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stratum(u8);

impl Stratum {
    /// Stratum 0: Kiss-o'-Death marker in server packets.
    pub const KISS_OF_DEATH: Self = Self(0);
    /// Stratum 16: unsynchronised.
    pub const UNSYNCHRONISED: Self = Self(16);

    /// Wraps a raw stratum byte without policy judgement (used by the parser).
    #[must_use]
    pub const fn from_raw(value: u8) -> Self {
        Self(value)
    }

    /// The raw stratum byte.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Validates a configured server stratum: 1-15 only. Stratum 0 and
    /// 16+ are not valid synchronised server strata.
    pub const fn for_server(value: u8) -> Result<Self, ConfigError> {
        match value {
            0 => Err(ConfigError::StratumZero),
            1..=15 => Ok(Self(value)),
            other => Err(ConfigError::StratumTooHigh(other)),
        }
    }

    /// Whether this is the Kiss-o'-Death stratum.
    #[must_use]
    pub const fn is_kiss_of_death(self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Display for Stratum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Signed 16.16 fixed-point value (root delay). One unit of the raw value
/// is 2⁻¹⁶ s ≈ 15.26 µs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NtpShortSigned(i32);

impl NtpShortSigned {
    /// Zero delay.
    pub const ZERO: Self = Self(0);

    /// Wraps the raw signed 16.16 bits.
    #[must_use]
    pub const fn from_bits(bits: i32) -> Self {
        Self(bits)
    }

    /// The raw signed 16.16 bits.
    #[must_use]
    pub const fn to_bits(self) -> i32 {
        self.0
    }

    /// Builds from milliseconds using exact integer arithmetic
    /// (`bits = ms * 65536 / 1000`, truncated toward zero).
    pub const fn from_millis(millis: i64) -> Result<Self, ConfigError> {
        let bits = millis * 65_536 / 1000;
        if bits > i32::MAX as i64 || bits < i32::MIN as i64 {
            return Err(ConfigError::FixedPointOutOfRange(millis));
        }
        Ok(Self(bits as i32))
    }

    /// Value in microseconds using exact integer arithmetic
    /// (truncated toward zero).
    #[must_use]
    pub const fn to_micros(self) -> i64 {
        self.0 as i64 * 1_000_000 / 65_536
    }

    /// Value in seconds as `f64`, for display only.
    #[must_use]
    pub fn to_seconds_f64(self) -> f64 {
        f64::from(self.0) / 65_536.0
    }

    /// Decodes from network-order bytes.
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(i32::from_be_bytes(bytes))
    }

    /// Encodes to network-order bytes.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// Unsigned 16.16 fixed-point value (root dispersion). Never negative.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NtpShortUnsigned(u32);

impl NtpShortUnsigned {
    /// Zero dispersion.
    pub const ZERO: Self = Self(0);

    /// Wraps the raw unsigned 16.16 bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw unsigned 16.16 bits.
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        self.0
    }

    /// Builds from milliseconds using exact integer arithmetic
    /// (`bits = ms * 65536 / 1000`, truncated toward zero). Rejects
    /// negative values: dispersion is non-negative by definition.
    pub const fn from_millis(millis: i64) -> Result<Self, ConfigError> {
        if millis < 0 {
            return Err(ConfigError::FixedPointOutOfRange(millis));
        }
        let bits = millis as u64 * 65_536 / 1000;
        if bits > u32::MAX as u64 {
            return Err(ConfigError::FixedPointOutOfRange(millis));
        }
        Ok(Self(bits as u32))
    }

    /// Value in microseconds using exact integer arithmetic.
    #[must_use]
    pub const fn to_micros(self) -> u64 {
        self.0 as u64 * 1_000_000 / 65_536
    }

    /// Value in seconds as `f64`, for display only.
    #[must_use]
    pub fn to_seconds_f64(self) -> f64 {
        f64::from(self.0) / 65_536.0
    }

    /// Decodes from network-order bytes.
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    /// Encodes to network-order bytes.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

/// Four-byte reference identifier.
///
/// The wire carries exactly four opaque bytes; no UTF-8 is assumed. Display
/// renders printable ASCII directly and anything else as hexadecimal.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceId([u8; 4]);

impl ReferenceId {
    /// Heeler's default reference identifier for secondary strata.
    pub const DEFAULT: Self = Self(*b"HLER");

    /// Wraps four raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// The four raw bytes as placed on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> [u8; 4] {
        self.0
    }

    /// Builds from a configured string of 1-4 printable ASCII characters,
    /// zero-padded on the right to exactly four bytes (the conventional
    /// encoding for identifiers like `"GPS"`).
    pub fn from_config(text: &str) -> Result<Self, ConfigError> {
        let bytes = text.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= 4
            && bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
        if !valid {
            return Err(ConfigError::InvalidReferenceId(text.to_owned()));
        }
        let mut out = [0u8; 4];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(Self(out))
    }
}

impl std::fmt::Display for ReferenceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let printable = self
            .0
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0);
        if printable && self.0[0] != 0 {
            for b in self.0.iter().take_while(|b| **b != 0) {
                write!(f, "{}", *b as char)?;
            }
            Ok(())
        } else {
            write!(
                f,
                "0x{:02X}{:02X}{:02X}{:02X}",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        }
    }
}

/// Kiss-o'-Death codes supported by Heeler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KissCode {
    /// `RATE` — the client is sending too fast and should reduce its rate.
    Rate,
    /// `DENY` — access is denied; the client should stop sending.
    Deny,
    /// `RSTR` — access is restricted by policy.
    Restrict,
}

impl KissCode {
    /// The four-byte reference identifier carried by the KoD packet.
    #[must_use]
    pub const fn reference_id(self) -> ReferenceId {
        match self {
            Self::Rate => ReferenceId(*b"RATE"),
            Self::Deny => ReferenceId(*b"DENY"),
            Self::Restrict => ReferenceId(*b"RSTR"),
        }
    }
}

/// A fully decoded 48-byte NTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpPacket {
    /// Leap indicator (2 bits).
    pub leap: LeapIndicator,
    /// Version number (3 bits).
    pub version: NtpVersion,
    /// Association mode (3 bits).
    pub mode: Mode,
    /// Stratum byte.
    pub stratum: Stratum,
    /// Poll exponent: signed log2 seconds.
    pub poll: i8,
    /// Precision exponent: signed log2 seconds.
    pub precision: i8,
    /// Root delay, signed 16.16 seconds.
    pub root_delay: NtpShortSigned,
    /// Root dispersion, unsigned 16.16 seconds.
    pub root_dispersion: NtpShortUnsigned,
    /// Reference identifier.
    pub reference_id: ReferenceId,
    /// Reference timestamp: when the clock source was last valid.
    pub reference_timestamp: NtpTimestamp,
    /// Origin timestamp (T1 as echoed to the client).
    pub origin_timestamp: NtpTimestamp,
    /// Receive timestamp (T2).
    pub receive_timestamp: NtpTimestamp,
    /// Transmit timestamp (T3, or T1 in a client request).
    pub transmit_timestamp: NtpTimestamp,
}

impl NtpPacket {
    /// Parses the 48-byte base packet from a datagram.
    ///
    /// Datagrams shorter than 48 bytes are rejected. Bytes beyond the base
    /// packet (extension fields, MACs) are *not* parsed; their length is
    /// reported in [`ParsedPacket::trailing_bytes`] so policy can decide.
    /// This function never panics and never allocates.
    pub fn parse(data: &[u8]) -> Result<ParsedPacket, ParseError> {
        if data.len() < PACKET_SIZE {
            return Err(ParseError::TooShort { actual: data.len() });
        }
        let flags = data[OFFSET_FLAGS];
        let packet = Self {
            leap: LeapIndicator::from_bits(flags >> 6),
            version: NtpVersion::from_bits(flags >> 3),
            mode: Mode::from_bits(flags),
            stratum: Stratum::from_raw(data[OFFSET_STRATUM]),
            poll: data[OFFSET_POLL] as i8,
            precision: data[OFFSET_PRECISION] as i8,
            root_delay: NtpShortSigned::from_be_bytes(read_4(data, OFFSET_ROOT_DELAY)),
            root_dispersion: NtpShortUnsigned::from_be_bytes(read_4(data, OFFSET_ROOT_DISPERSION)),
            reference_id: ReferenceId::from_bytes(read_4(data, OFFSET_REFERENCE_ID)),
            reference_timestamp: NtpTimestamp::from_be_bytes(read_8(data, OFFSET_REFERENCE_TS)),
            origin_timestamp: NtpTimestamp::from_be_bytes(read_8(data, OFFSET_ORIGIN_TS)),
            receive_timestamp: NtpTimestamp::from_be_bytes(read_8(data, OFFSET_RECEIVE_TS)),
            transmit_timestamp: NtpTimestamp::from_be_bytes(read_8(data, OFFSET_TRANSMIT_TS)),
        };
        Ok(ParsedPacket {
            packet,
            trailing_bytes: data.len() - PACKET_SIZE,
        })
    }

    /// Encodes the packet as 48 network-order bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; PACKET_SIZE] {
        let mut out = [0u8; PACKET_SIZE];
        out[OFFSET_FLAGS] =
            (self.leap.to_bits() << 6) | (self.version.to_bits() << 3) | self.mode.to_bits();
        out[OFFSET_STRATUM] = self.stratum.value();
        out[OFFSET_POLL] = self.poll as u8;
        out[OFFSET_PRECISION] = self.precision as u8;
        write_4(&mut out, OFFSET_ROOT_DELAY, self.root_delay.to_be_bytes());
        write_4(
            &mut out,
            OFFSET_ROOT_DISPERSION,
            self.root_dispersion.to_be_bytes(),
        );
        write_4(&mut out, OFFSET_REFERENCE_ID, self.reference_id.as_bytes());
        write_8(
            &mut out,
            OFFSET_REFERENCE_TS,
            self.reference_timestamp.to_be_bytes(),
        );
        write_8(
            &mut out,
            OFFSET_ORIGIN_TS,
            self.origin_timestamp.to_be_bytes(),
        );
        write_8(
            &mut out,
            OFFSET_RECEIVE_TS,
            self.receive_timestamp.to_be_bytes(),
        );
        write_8(
            &mut out,
            OFFSET_TRANSMIT_TS,
            self.transmit_timestamp.to_be_bytes(),
        );
        out
    }
}

/// The result of parsing a datagram: the decoded base packet plus the number
/// of unparsed trailing bytes (extension fields / MAC data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacket {
    /// The decoded 48-byte base packet.
    pub packet: NtpPacket,
    /// Bytes present after the base packet that were not interpreted.
    pub trailing_bytes: usize,
}

fn read_4(data: &[u8], offset: usize) -> [u8; 4] {
    [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]
}

fn read_8(data: &[u8], offset: usize) -> [u8; 8] {
    [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]
}

fn write_4(out: &mut [u8; PACKET_SIZE], offset: usize, bytes: [u8; 4]) {
    out[offset..offset + 4].copy_from_slice(&bytes);
}

fn write_8(out: &mut [u8; PACKET_SIZE], offset: usize, bytes: [u8; 8]) {
    out[offset..offset + 8].copy_from_slice(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-constructed NTPv4 client request (as sent by common SNTP
    /// clients): LI=0, VN=4, mode=3, all fields zero except the transmit
    /// timestamp 0xE3B0F2AC.80000000 (2021-01-15-ish, fraction 0.5 s).
    const GOLDEN_CLIENT_REQUEST: [u8; 48] = [
        0x23, 0x00, 0x06, 0xEC, // LI/VN/Mode, stratum, poll, precision (-20)
        0x00, 0x00, 0x00, 0x00, // root delay
        0x00, 0x00, 0x00, 0x00, // root dispersion
        0x00, 0x00, 0x00, 0x00, // reference id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reference ts
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // origin ts
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // receive ts
        0xE3, 0xB0, 0xF2, 0xAC, 0x80, 0x00, 0x00, 0x00, // transmit ts
    ];

    #[test]
    fn golden_client_request_parses() {
        let parsed = NtpPacket::parse(&GOLDEN_CLIENT_REQUEST).unwrap();
        assert_eq!(parsed.trailing_bytes, 0);
        let p = parsed.packet;
        assert_eq!(p.leap, LeapIndicator::NoWarning);
        assert_eq!(p.version, NtpVersion::V4);
        assert_eq!(p.mode, Mode::Client);
        assert_eq!(p.stratum.value(), 0);
        assert_eq!(p.poll, 6);
        assert_eq!(p.precision, -20);
        assert_eq!(p.root_delay, NtpShortSigned::ZERO);
        assert_eq!(p.root_dispersion, NtpShortUnsigned::ZERO);
        assert!(p.origin_timestamp.is_zero());
        assert!(p.receive_timestamp.is_zero());
        assert_eq!(
            p.transmit_timestamp,
            NtpTimestamp::new(0xE3B0_F2AC, 0x8000_0000)
        );
    }

    #[test]
    fn golden_client_request_reencodes_identically() {
        let parsed = NtpPacket::parse(&GOLDEN_CLIENT_REQUEST).unwrap();
        assert_eq!(parsed.packet.encode(), GOLDEN_CLIENT_REQUEST);
    }

    /// A hand-constructed NTPv3 server response: LI=0, VN=3, mode=4,
    /// stratum 2, poll 6, precision -23, root delay 0x00000800 (~31 ms),
    /// root dispersion 0x00000400 (~15.6 ms), refid "HLER".
    const GOLDEN_SERVER_RESPONSE: [u8; 48] = [
        0x1C, 0x02, 0x06, 0xE9, // LI=0 VN=3 Mode=4, stratum 2, poll 6, prec -23
        0x00, 0x00, 0x08, 0x00, // root delay
        0x00, 0x00, 0x04, 0x00, // root dispersion
        0x48, 0x4C, 0x45, 0x52, // "HLER"
        0xE3, 0xB0, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, // reference ts
        0xE3, 0xB0, 0xF2, 0xAC, 0x80, 0x00, 0x00, 0x00, // origin ts (= client T1)
        0xE3, 0xB0, 0xF2, 0xAD, 0x00, 0x00, 0x00, 0x00, // receive ts
        0xE3, 0xB0, 0xF2, 0xAD, 0x40, 0x00, 0x00, 0x00, // transmit ts
    ];

    #[test]
    fn golden_server_response_parses() {
        let parsed = NtpPacket::parse(&GOLDEN_SERVER_RESPONSE).unwrap();
        let p = parsed.packet;
        assert_eq!(p.leap, LeapIndicator::NoWarning);
        assert_eq!(p.version, NtpVersion::V3);
        assert_eq!(p.mode, Mode::Server);
        assert_eq!(p.stratum.value(), 2);
        assert_eq!(p.precision, -23);
        assert_eq!(p.root_delay.to_bits(), 0x0800);
        assert_eq!(p.root_dispersion.to_bits(), 0x0400);
        assert_eq!(p.reference_id, ReferenceId::from_bytes(*b"HLER"));
        assert_eq!(
            p.origin_timestamp,
            NtpTimestamp::new(0xE3B0_F2AC, 0x8000_0000)
        );
        assert_eq!(p.encode(), GOLDEN_SERVER_RESPONSE);
    }

    #[test]
    fn short_packets_are_rejected() {
        for len in 0..PACKET_SIZE {
            let data = vec![0u8; len];
            assert_eq!(
                NtpPacket::parse(&data),
                Err(ParseError::TooShort { actual: len })
            );
        }
    }

    #[test]
    fn trailing_bytes_are_reported_not_misparsed() {
        let mut data = GOLDEN_CLIENT_REQUEST.to_vec();
        data.extend_from_slice(&[0xFF; 20]);
        let parsed = NtpPacket::parse(&data).unwrap();
        assert_eq!(parsed.trailing_bytes, 20);
        // Base fields are unaffected by trailing data.
        assert_eq!(parsed.packet.encode(), GOLDEN_CLIENT_REQUEST);
    }

    #[test]
    fn flag_byte_bit_packing() {
        for li in 0..4u8 {
            for vn in 0..8u8 {
                for mode in 0..8u8 {
                    let byte = (li << 6) | (vn << 3) | mode;
                    let mut data = [0u8; PACKET_SIZE];
                    data[0] = byte;
                    let p = NtpPacket::parse(&data).unwrap().packet;
                    assert_eq!(p.leap.to_bits(), li);
                    assert_eq!(p.version.to_bits(), vn);
                    assert_eq!(p.mode.to_bits(), mode);
                    assert_eq!(p.encode()[0], byte);
                }
            }
        }
    }

    #[test]
    fn poll_and_precision_are_signed() {
        let mut data = [0u8; PACKET_SIZE];
        data[2] = 0xFA; // poll -6
        data[3] = 0xEC; // precision -20
        let p = NtpPacket::parse(&data).unwrap().packet;
        assert_eq!(p.poll, -6);
        assert_eq!(p.precision, -20);
        let encoded = p.encode();
        assert_eq!(encoded[2], 0xFA);
        assert_eq!(encoded[3], 0xEC);
    }

    #[test]
    fn root_delay_is_signed_root_dispersion_is_not() {
        let mut data = [0u8; PACKET_SIZE];
        data[4..8].copy_from_slice(&[0xFF, 0xFF, 0x80, 0x00]); // -0.5 s
        data[8..12].copy_from_slice(&[0xFF, 0xFF, 0x80, 0x00]); // large positive
        let p = NtpPacket::parse(&data).unwrap().packet;
        assert!(p.root_delay.to_bits() < 0);
        assert_eq!(p.root_delay.to_micros(), -500_000);
        assert_eq!(p.root_dispersion.to_bits(), 0xFFFF_8000);
    }

    #[test]
    fn ntp_short_millis_conversion() {
        assert_eq!(NtpShortSigned::from_millis(1000).unwrap().to_bits(), 65_536);
        assert_eq!(NtpShortSigned::from_millis(0).unwrap().to_bits(), 0);
        assert_eq!(
            NtpShortSigned::from_millis(-1000).unwrap().to_bits(),
            -65_536
        );
        assert_eq!(NtpShortUnsigned::from_millis(5).unwrap().to_bits(), 327);
        assert!(NtpShortUnsigned::from_millis(-1).is_err());
        assert!(NtpShortSigned::from_millis(40_000_000).is_err());
        assert!(NtpShortUnsigned::from_millis(70_000_000).is_err());
    }

    #[test]
    fn reference_id_display() {
        assert_eq!(ReferenceId::from_bytes(*b"GPS\0").to_string(), "GPS");
        assert_eq!(ReferenceId::from_bytes(*b"HLER").to_string(), "HLER");
        assert_eq!(
            ReferenceId::from_bytes([0x01, 0x02, 0x03, 0x04]).to_string(),
            "0x01020304"
        );
    }

    #[test]
    fn reference_id_from_config() {
        assert_eq!(
            ReferenceId::from_config("GPS").unwrap().as_bytes(),
            *b"GPS\0"
        );
        assert!(ReferenceId::from_config("").is_err());
        assert!(ReferenceId::from_config("TOOLONG").is_err());
        assert!(ReferenceId::from_config("a\u{1F980}").is_err());
    }

    #[test]
    fn stratum_validation() {
        assert!(Stratum::for_server(0).is_err());
        assert!(Stratum::for_server(1).is_ok());
        assert!(Stratum::for_server(15).is_ok());
        assert!(Stratum::for_server(16).is_err());
        assert!(Stratum::for_server(255).is_err());
    }

    #[test]
    fn kiss_codes() {
        assert_eq!(KissCode::Rate.reference_id().as_bytes(), *b"RATE");
        assert_eq!(KissCode::Deny.reference_id().as_bytes(), *b"DENY");
        assert_eq!(KissCode::Restrict.reference_id().as_bytes(), *b"RSTR");
    }
}
