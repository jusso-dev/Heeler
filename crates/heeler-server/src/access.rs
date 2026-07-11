//! CIDR-based source-address access control.
//!
//! # Precedence
//!
//! For a given source address, the longest (most specific) matching prefix
//! wins across both lists; on a tie in prefix length, **deny wins**. When no
//! rule matches, the configured default action applies. An exact-address
//! deny (`/32` or `/128`) therefore always beats any allow.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are canonicalised to IPv4
//! before evaluation so v4 rules apply regardless of socket family.

use std::net::IpAddr;

use ipnet::IpNet;

/// Errors building the access-control table.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    /// A rule was neither a CIDR prefix nor a bare IP address.
    #[error("invalid CIDR rule {0:?}")]
    InvalidRule(String),
    /// The default action was not `allow` or `deny`.
    #[error("invalid default_action {0:?}: must be \"allow\" or \"deny\"")]
    InvalidDefaultAction(String),
}

/// The outcome of an access-control evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// The source may be answered.
    Allowed,
    /// The source must not be answered.
    Denied,
}

/// Compiled allow/deny rule table.
#[derive(Debug, Clone)]
pub struct AccessControl {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
    default_allow: bool,
}

impl AccessControl {
    /// Compiles rule strings. Each rule is a CIDR prefix (`10.0.0.0/8`) or a
    /// bare address (`127.0.0.1`, treated as `/32` or `/128`).
    pub fn from_rules(
        allow: &[String],
        deny: &[String],
        default_action: &str,
    ) -> Result<Self, AccessError> {
        let default_allow = match default_action {
            "allow" => true,
            "deny" => false,
            other => return Err(AccessError::InvalidDefaultAction(other.to_owned())),
        };
        Ok(Self {
            allow: parse_rules(allow)?,
            deny: parse_rules(deny)?,
            default_allow,
        })
    }

    /// Evaluates a source address against the table.
    #[must_use]
    pub fn evaluate(&self, source: IpAddr) -> AccessDecision {
        let source = canonicalise(source);
        let best_allow = longest_match(&self.allow, source);
        let best_deny = longest_match(&self.deny, source);
        match (best_allow, best_deny) {
            // Tie in specificity: deny wins.
            (Some(allow), Some(deny)) if deny >= allow => AccessDecision::Denied,
            (Some(_), Some(_)) | (Some(_), None) => AccessDecision::Allowed,
            (None, Some(_)) => AccessDecision::Denied,
            (None, None) => {
                if self.default_allow {
                    AccessDecision::Allowed
                } else {
                    AccessDecision::Denied
                }
            }
        }
    }
}

fn parse_rules(rules: &[String]) -> Result<Vec<IpNet>, AccessError> {
    rules
        .iter()
        .map(|rule| {
            rule.parse::<IpNet>()
                .or_else(|_| rule.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| AccessError::InvalidRule(rule.clone()))
        })
        .collect()
}

/// The longest matching prefix length in `nets` for `ip`, if any.
fn longest_match(nets: &[IpNet], ip: IpAddr) -> Option<u8> {
    nets.iter()
        .filter(|net| net.contains(&ip))
        .map(IpNet::prefix_len)
        .max()
}

/// Converts IPv4-mapped IPv6 addresses to their IPv4 form.
fn canonicalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(allow: &[&str], deny: &[&str], default_action: &str) -> AccessControl {
        AccessControl::from_rules(
            &allow.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            &deny.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            default_action,
        )
        .unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_deny_with_loopback_allow() {
        let acl = table(&["127.0.0.0/8", "::1/128"], &[], "deny");
        assert_eq!(acl.evaluate(ip("127.0.0.1")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("127.1.2.3")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("::1")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("10.0.0.1")), AccessDecision::Denied);
        assert_eq!(acl.evaluate(ip("8.8.8.8")), AccessDecision::Denied);
        assert_eq!(acl.evaluate(ip("2001:db8::1")), AccessDecision::Denied);
    }

    #[test]
    fn more_specific_deny_beats_allow() {
        let acl = table(&["10.0.0.0/8"], &["10.1.0.0/16"], "deny");
        assert_eq!(acl.evaluate(ip("10.2.0.1")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("10.1.0.1")), AccessDecision::Denied);
    }

    #[test]
    fn more_specific_allow_beats_deny() {
        let acl = table(&["10.1.1.0/24"], &["10.0.0.0/8"], "deny");
        assert_eq!(acl.evaluate(ip("10.1.1.7")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("10.9.9.9")), AccessDecision::Denied);
    }

    #[test]
    fn equal_specificity_deny_wins() {
        let acl = table(&["10.0.0.0/8"], &["10.0.0.0/8"], "allow");
        assert_eq!(acl.evaluate(ip("10.5.5.5")), AccessDecision::Denied);
    }

    #[test]
    fn exact_deny_beats_everything() {
        let acl = table(&["0.0.0.0/0"], &["192.168.1.99"], "allow");
        assert_eq!(acl.evaluate(ip("192.168.1.98")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("192.168.1.99")), AccessDecision::Denied);
    }

    #[test]
    fn default_allow_when_no_match() {
        let acl = table(&[], &["192.0.2.0/24"], "allow");
        assert_eq!(acl.evaluate(ip("198.51.100.1")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("192.0.2.55")), AccessDecision::Denied);
    }

    #[test]
    fn ipv6_rules() {
        let acl = table(&["fc00::/7"], &["fd00:bad::/32"], "deny");
        assert_eq!(acl.evaluate(ip("fd12::1")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("fd00:bad::1")), AccessDecision::Denied);
        assert_eq!(acl.evaluate(ip("2001:db8::1")), AccessDecision::Denied);
    }

    #[test]
    fn ipv4_mapped_ipv6_uses_v4_rules() {
        let acl = table(&["127.0.0.0/8"], &[], "deny");
        assert_eq!(
            acl.evaluate(ip("::ffff:127.0.0.1")),
            AccessDecision::Allowed
        );
        assert_eq!(acl.evaluate(ip("::ffff:8.8.8.8")), AccessDecision::Denied);
    }

    #[test]
    fn bare_addresses_accepted_as_rules() {
        let acl = table(&["192.0.2.1"], &[], "deny");
        assert_eq!(acl.evaluate(ip("192.0.2.1")), AccessDecision::Allowed);
        assert_eq!(acl.evaluate(ip("192.0.2.2")), AccessDecision::Denied);
    }

    #[test]
    fn invalid_rules_rejected() {
        assert!(AccessControl::from_rules(&["not-a-cidr".to_owned()], &[], "deny").is_err());
        assert!(AccessControl::from_rules(&[], &[], "maybe").is_err());
    }
}
