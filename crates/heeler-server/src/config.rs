//! Configuration loading, layering, and validation.
//!
//! Precedence (highest wins): CLI flags, then environment variables, then
//! the TOML file, then built-in defaults. All values are validated before
//! any socket is opened; invalid values produce startup errors rather than
//! being silently clamped.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use heeler_core::packet::{LeapIndicator, NtpShortSigned, NtpShortUnsigned, ReferenceId, Stratum};
use heeler_core::response::ServerIdentity;
use heeler_core::validation::ValidationPolicy;
use serde::{Deserialize, Serialize};

use crate::access::AccessControl;

/// Errors produced while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    /// The configuration file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Io {
        /// Path that failed to load.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The configuration file is not valid TOML for the expected schema.
    #[error("invalid config file {path}: {source}")]
    Parse {
        /// Path that failed to parse.
        path: String,
        /// Underlying TOML error.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// An environment variable held an unusable value.
    #[error("invalid environment variable {name}={value}: {reason}")]
    Env {
        /// Variable name.
        name: String,
        /// Observed value.
        value: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A semantic validation failure.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Top-level configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Socket and process options.
    pub server: ServerSection,
    /// NTP protocol behaviour.
    pub protocol: ProtocolSection,
    /// Clock-source behaviour.
    pub clock: ClockSection,
    /// CIDR access control.
    pub access: AccessSection,
    /// Rate limiting.
    pub rate_limit: RateLimitSection,
    /// Logging.
    pub logging: LoggingSection,
    /// Optional Prometheus metrics.
    pub metrics: MetricsSection,
    /// Privilege handling.
    pub security: SecuritySection,
}

/// `[server]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSection {
    /// Addresses to bind. Loopback only by default: exposing an NTP server
    /// is an explicit operator decision.
    pub bind: Vec<SocketAddr>,
    /// Reserved for future use; must be 1 in this release.
    pub workers: u32,
    /// Largest datagram accepted, in bytes (48-1024).
    pub max_packet_size: usize,
    /// Refuse to start on a public (non-loopback, non-private) address
    /// unless `public_bind_acknowledged` is set.
    pub strict_public_bind: bool,
    /// Operator acknowledgement for public binds.
    pub public_bind_acknowledged: bool,
    /// Socket receive buffer size in bytes (0 = OS default).
    pub recv_buffer_bytes: usize,
    /// Socket send buffer size in bytes (0 = OS default).
    pub send_buffer_bytes: usize,
    /// Set SO_REUSEADDR on the listening sockets.
    pub reuse_addr: bool,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            bind: vec![
                "127.0.0.1:123".parse().unwrap_or_else(|_| unreachable!()),
                "[::1]:123".parse().unwrap_or_else(|_| unreachable!()),
            ],
            workers: 1,
            max_packet_size: 512,
            strict_public_bind: true,
            public_bind_acknowledged: false,
            recv_buffer_bytes: 0,
            send_buffer_bytes: 0,
            reuse_addr: false,
        }
    }
}

/// `[protocol]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtocolSection {
    /// NTP versions answered.
    pub versions: Vec<u8>,
    /// Advertised stratum (1-15).
    pub stratum: u8,
    /// Reference identifier: 1-4 printable ASCII characters.
    pub reference_id: String,
    /// Default poll exponent when the client's is unusable.
    pub poll: i8,
    /// Advertised precision exponent; when unset, measured at startup.
    pub precision: Option<i8>,
    /// Advertised root delay in milliseconds.
    pub root_delay_ms: i64,
    /// Advertised root dispersion in milliseconds.
    pub root_dispersion_ms: i64,
    /// Leap indicator advertised while synchronised (0-3).
    pub leap_indicator: u8,
    /// Reject client requests with a zero transmit timestamp.
    pub require_nonzero_transmit_timestamp: bool,
    /// Accept datagrams with trailing bytes after the base packet.
    pub allow_trailing_data: bool,
    /// Answer per-client rate-limited requests with a RATE Kiss-o'-Death.
    pub send_kod_on_rate_limit: bool,
    /// Answer policy-denied requests with a DENY Kiss-o'-Death. Off by
    /// default: silent drop reveals nothing to address scanners.
    pub send_kod_on_policy_deny: bool,
    /// Silently drop malformed packets (recommended). When false they are
    /// still dropped, but logged at debug level individually.
    pub silently_drop_malformed: bool,
}

impl Default for ProtocolSection {
    fn default() -> Self {
        Self {
            versions: vec![3, 4],
            stratum: 2,
            reference_id: "HLER".to_owned(),
            poll: 6,
            precision: None,
            root_delay_ms: 0,
            root_dispersion_ms: 5,
            leap_indicator: 0,
            require_nonzero_transmit_timestamp: false,
            allow_trailing_data: false,
            send_kod_on_rate_limit: true,
            send_kod_on_policy_deny: false,
            silently_drop_malformed: true,
        }
    }
}

/// `[clock]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClockSection {
    /// Clock source. Only `"system"` is supported in this release.
    pub source: String,
    /// Mark the server unsynchronised when a jump is detected.
    pub mark_unsynchronised_on_jump: bool,
    /// Maximum tolerated backward wall-clock movement (ms).
    pub max_backward_jump_ms: u64,
    /// Maximum tolerated forward wall-clock movement (ms).
    pub max_forward_jump_ms: u64,
}

impl Default for ClockSection {
    fn default() -> Self {
        Self {
            source: "system".to_owned(),
            mark_unsynchronised_on_jump: true,
            max_backward_jump_ms: 250,
            max_forward_jump_ms: 5000,
        }
    }
}

/// `[access]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessSection {
    /// CIDR prefixes (or bare addresses) allowed to query.
    pub allow: Vec<String>,
    /// CIDR prefixes (or bare addresses) refused.
    pub deny: Vec<String>,
    /// `"allow"` or `"deny"` when no rule matches.
    pub default_action: String,
}

impl Default for AccessSection {
    fn default() -> Self {
        Self {
            allow: vec!["127.0.0.0/8".to_owned(), "::1/128".to_owned()],
            deny: vec![],
            default_action: "deny".to_owned(),
        }
    }
}

/// `[rate_limit]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitSection {
    /// Master switch.
    pub enabled: bool,
    /// Sustained per-client requests per second.
    pub requests_per_second: u32,
    /// Per-client burst size.
    pub burst: u32,
    /// Sustained global requests per second (0 disables the global bucket).
    pub global_requests_per_second: u32,
    /// Global burst size.
    pub global_burst: u32,
    /// Idle client entries expire after this many seconds.
    pub client_entry_ttl_seconds: u64,
    /// Upper bound on tracked clients; the limiter fails closed when full.
    pub max_client_entries: usize,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 4,
            burst: 8,
            global_requests_per_second: 10_000,
            global_burst: 20_000,
            client_entry_ttl_seconds: 600,
            max_client_entries: 100_000,
        }
    }
}

/// `[logging]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingSection {
    /// `"pretty"`, `"compact"`, or `"json"`.
    pub format: String,
    /// Log level filter (`error`..`trace`).
    pub level: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            format: "pretty".to_owned(),
            level: "info".to_owned(),
        }
    }
}

/// `[metrics]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsSection {
    /// Enable the Prometheus text endpoint.
    pub enabled: bool,
    /// Bind address for the metrics HTTP listener (loopback by default).
    pub bind: SocketAddr,
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9180".parse().unwrap_or_else(|_| unreachable!()),
        }
    }
}

/// `[security]` section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecuritySection {
    /// Drop root privileges after binding sockets (Unix only; a no-op when
    /// not started as root).
    pub drop_privileges: bool,
    /// Target user (name or numeric UID).
    pub user: String,
    /// Target group (name or numeric GID).
    pub group: String,
    /// Optional chroot directory ("" disables).
    pub chroot_dir: String,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            drop_privileges: true,
            user: "heeler".to_owned(),
            group: "heeler".to_owned(),
            chroot_dir: String::new(),
        }
    }
}

impl Config {
    /// Loads configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigLoadError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigLoadError::Io {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigLoadError::Parse {
            path: path.display().to_string(),
            source: Box::new(source),
        })
    }

    /// Applies supported `HEELER_*` environment variables on top of the
    /// current values. Unset variables leave values untouched.
    pub fn apply_env_overrides(&mut self) -> Result<(), ConfigLoadError> {
        fn env_var(name: &str) -> Option<String> {
            std::env::var(name).ok().filter(|v| !v.is_empty())
        }
        fn parse<T: std::str::FromStr>(
            name: &str,
            value: &str,
            what: &str,
        ) -> Result<T, ConfigLoadError> {
            value.parse().map_err(|_| ConfigLoadError::Env {
                name: name.to_owned(),
                value: value.to_owned(),
                reason: format!("expected {what}"),
            })
        }

        if let Some(v) = env_var("HEELER_BIND") {
            let mut binds = Vec::new();
            for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                binds.push(parse::<SocketAddr>("HEELER_BIND", part, "socket address")?);
            }
            if binds.is_empty() {
                return Err(ConfigLoadError::Env {
                    name: "HEELER_BIND".to_owned(),
                    value: v,
                    reason: "expected at least one socket address".to_owned(),
                });
            }
            self.server.bind = binds;
        }
        if let Some(v) = env_var("HEELER_LOG_LEVEL") {
            self.logging.level = v;
        }
        if let Some(v) = env_var("HEELER_LOG_FORMAT") {
            self.logging.format = v;
        }
        if let Some(v) = env_var("HEELER_STRATUM") {
            self.protocol.stratum = parse("HEELER_STRATUM", &v, "an integer 1-15")?;
        }
        if let Some(v) = env_var("HEELER_REFERENCE_ID") {
            self.protocol.reference_id = v;
        }
        if let Some(v) = env_var("HEELER_METRICS_ENABLED") {
            self.metrics.enabled = parse("HEELER_METRICS_ENABLED", &v, "true or false")?;
        }
        if let Some(v) = env_var("HEELER_METRICS_BIND") {
            self.metrics.bind = parse("HEELER_METRICS_BIND", &v, "socket address")?;
        }
        if let Some(v) = env_var("HEELER_RATE_LIMIT_ENABLED") {
            self.rate_limit.enabled = parse("HEELER_RATE_LIMIT_ENABLED", &v, "true or false")?;
        }
        if let Some(v) = env_var("HEELER_PUBLIC_BIND_ACKNOWLEDGED") {
            self.server.public_bind_acknowledged =
                parse("HEELER_PUBLIC_BIND_ACKNOWLEDGED", &v, "true or false")?;
        }
        Ok(())
    }

    /// Validates every section and resolves derived values. Called before
    /// any socket is opened.
    pub fn validate(&self) -> Result<ValidatedConfig, ConfigLoadError> {
        let invalid = |msg: String| ConfigLoadError::Invalid(msg);

        // [server]
        if self.server.bind.is_empty() {
            return Err(invalid("server.bind must list at least one address".into()));
        }
        if self.server.workers != 1 {
            return Err(invalid(format!(
                "server.workers = {} is not supported: this release uses one \
                 receive loop per socket (the field is reserved)",
                self.server.workers
            )));
        }
        if self.server.max_packet_size < heeler_core::PACKET_SIZE
            || self.server.max_packet_size > 1024
        {
            return Err(invalid(format!(
                "server.max_packet_size = {} must be between 48 and 1024",
                self.server.max_packet_size
            )));
        }

        // [protocol]
        if self.protocol.versions.is_empty() {
            return Err(invalid("protocol.versions must not be empty".into()));
        }
        for v in &self.protocol.versions {
            if !(3..=4).contains(v) {
                return Err(invalid(format!(
                    "protocol.versions contains {v}: only versions 3 and 4 are served"
                )));
            }
        }
        let stratum = Stratum::for_server(self.protocol.stratum)
            .map_err(|e| invalid(format!("protocol.stratum: {e}")))?;
        let reference_id = ReferenceId::from_config(&self.protocol.reference_id)
            .map_err(|e| invalid(format!("protocol.reference_id: {e}")))?;
        if self.protocol.stratum == 1 && self.protocol.reference_id == "HLER" {
            return Err(invalid(
                "protocol.stratum = 1 requires an explicit reference_id naming the \
                 reference source (e.g. \"GPS\", \"PPS\", \"LOCL\"); Heeler will not \
                 claim to be a primary server by default"
                    .into(),
            ));
        }
        let leap = LeapIndicator::from_config(self.protocol.leap_indicator)
            .map_err(|e| invalid(format!("protocol.leap_indicator: {e}")))?;
        if !(0..=17).contains(&self.protocol.poll) {
            return Err(invalid(format!(
                "protocol.poll = {} must be between 0 and 17",
                self.protocol.poll
            )));
        }
        if let Some(p) = self.protocol.precision {
            if !(-30..=0).contains(&p) {
                return Err(invalid(format!(
                    "protocol.precision = {p} must be between -30 and 0"
                )));
            }
        }
        let root_delay = NtpShortSigned::from_millis(self.protocol.root_delay_ms)
            .map_err(|e| invalid(format!("protocol.root_delay_ms: {e}")))?;
        let root_dispersion = NtpShortUnsigned::from_millis(self.protocol.root_dispersion_ms)
            .map_err(|e| invalid(format!("protocol.root_dispersion_ms: {e}")))?;

        // [clock]
        if self.clock.source != "system" {
            return Err(invalid(format!(
                "clock.source = {:?}: only \"system\" is supported in this release",
                self.clock.source
            )));
        }
        if self.clock.max_backward_jump_ms == 0 || self.clock.max_forward_jump_ms == 0 {
            return Err(invalid(
                "clock jump thresholds must be positive milliseconds".into(),
            ));
        }

        // [access]
        let access = AccessControl::from_rules(
            &self.access.allow,
            &self.access.deny,
            &self.access.default_action,
        )
        .map_err(|e| invalid(format!("access: {e}")))?;

        // [rate_limit]
        if self.rate_limit.enabled {
            if self.rate_limit.requests_per_second == 0 || self.rate_limit.burst == 0 {
                return Err(invalid(
                    "rate_limit.requests_per_second and rate_limit.burst must be \
                     positive when rate limiting is enabled"
                        .into(),
                ));
            }
            if self.rate_limit.max_client_entries == 0 {
                return Err(invalid(
                    "rate_limit.max_client_entries must be positive".into(),
                ));
            }
            if self.rate_limit.client_entry_ttl_seconds == 0 {
                return Err(invalid(
                    "rate_limit.client_entry_ttl_seconds must be positive".into(),
                ));
            }
        }

        // [logging]
        if !["pretty", "compact", "json"].contains(&self.logging.format.as_str()) {
            return Err(invalid(format!(
                "logging.format = {:?} must be \"pretty\", \"compact\", or \"json\"",
                self.logging.format
            )));
        }

        // [security]
        if self.security.drop_privileges && self.security.user.is_empty() {
            return Err(invalid(
                "security.user must be set when security.drop_privileges = true".into(),
            ));
        }

        let identity = ServerIdentity {
            stratum,
            reference_id,
            // Placeholder; replaced by the measured value at startup when
            // protocol.precision is unset.
            precision: self.protocol.precision.unwrap_or(-20),
            root_delay,
            root_dispersion,
            default_poll: self.protocol.poll,
            leap,
        };

        Ok(ValidatedConfig {
            config: self.clone(),
            identity,
            precision_configured: self.protocol.precision.is_some(),
            access,
            validation_policy: ValidationPolicy {
                supported_versions: self.protocol.versions.clone(),
                require_nonzero_transmit_timestamp: self
                    .protocol
                    .require_nonzero_transmit_timestamp,
                allow_trailing_data: self.protocol.allow_trailing_data,
            },
            jump_policy: heeler_core::clock::JumpPolicy {
                max_backward: Duration::from_millis(self.clock.max_backward_jump_ms),
                max_forward: Duration::from_millis(self.clock.max_forward_jump_ms),
                mark_unsynchronised_on_jump: self.clock.mark_unsynchronised_on_jump,
            },
        })
    }

    /// Addresses in `server.bind` that are neither loopback nor RFC 1918 /
    /// ULA / link-local private space (unspecified addresses count as
    /// public: they accept traffic from anywhere).
    #[must_use]
    pub fn public_bind_addresses(&self) -> Vec<SocketAddr> {
        self.server
            .bind
            .iter()
            .filter(|addr| is_public_address(addr))
            .copied()
            .collect()
    }
}

fn is_public_address(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => !(ip.is_loopback() || ip.is_private() || ip.is_link_local()),
        std::net::IpAddr::V6(ip) => {
            let is_ula = (ip.segments()[0] & 0xfe00) == 0xfc00;
            let is_link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
            !(ip.is_loopback() || is_ula || is_link_local)
        }
    }
}

/// The result of successful validation: the raw config plus derived,
/// strongly typed pieces ready for the server runtime.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// The validated raw configuration.
    pub config: Config,
    /// Server identity for response building. `precision` is the configured
    /// value or a placeholder when `precision_configured` is false.
    pub identity: ServerIdentity,
    /// Whether `identity.precision` came from configuration (vs to-measure).
    pub precision_configured: bool,
    /// Compiled access-control rules.
    pub access: AccessControl,
    /// Compiled packet validation policy.
    pub validation_policy: ValidationPolicy,
    /// Compiled clock jump policy.
    pub jump_policy: heeler_core::clock::JumpPolicy,
}

/// The documented default configuration, printed by
/// `heeler print-default-config`. Kept in sync with `Config::default()` by
/// a unit test.
pub const DEFAULT_CONFIG_TOML: &str = include_str!("../../../config/heeler.example.toml");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn example_config_matches_defaults() {
        let parsed: Config = toml::from_str(DEFAULT_CONFIG_TOML).unwrap();
        let defaults = Config::default();
        // Compare via serialisation: Config has no Eq.
        assert_eq!(
            toml::to_string(&parsed).unwrap(),
            toml::to_string(&defaults).unwrap(),
            "config/heeler.example.toml must match built-in defaults"
        );
    }

    #[test]
    fn stratum_validation() {
        let mut config = Config::default();
        config.protocol.stratum = 0;
        assert!(config.validate().is_err());
        config.protocol.stratum = 16;
        assert!(config.validate().is_err());
        config.protocol.stratum = 15;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn stratum_one_requires_explicit_reference_id() {
        let mut config = Config::default();
        config.protocol.stratum = 1;
        assert!(config.validate().is_err());
        config.protocol.reference_id = "GPS".to_owned();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn unsupported_versions_rejected() {
        let mut config = Config::default();
        config.protocol.versions = vec![2];
        assert!(config.validate().is_err());
        config.protocol.versions = vec![];
        assert!(config.validate().is_err());
        config.protocol.versions = vec![4];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn packet_size_bounds() {
        let mut config = Config::default();
        config.server.max_packet_size = 47;
        assert!(config.validate().is_err());
        config.server.max_packet_size = 2048;
        assert!(config.validate().is_err());
        config.server.max_packet_size = 48;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn workers_reserved() {
        let mut config = Config::default();
        config.server.workers = 4;
        assert!(config.validate().is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("[server]\nbogus_key = 1\n");
        assert!(err.is_err());
    }

    #[test]
    fn public_bind_detection() {
        let mut config = Config::default();
        assert!(config.public_bind_addresses().is_empty());
        config.server.bind = vec!["0.0.0.0:123".parse().unwrap()];
        assert_eq!(config.public_bind_addresses().len(), 1);
        config.server.bind = vec!["192.168.1.10:123".parse().unwrap()];
        assert!(config.public_bind_addresses().is_empty());
        config.server.bind = vec!["[::]:123".parse().unwrap()];
        assert_eq!(config.public_bind_addresses().len(), 1);
        config.server.bind = vec!["[fd00::1]:123".parse().unwrap()];
        assert!(config.public_bind_addresses().is_empty());
    }

    #[test]
    fn clock_source_must_be_system() {
        let mut config = Config::default();
        config.clock.source = "gps".to_owned();
        assert!(config.validate().is_err());
    }
}
