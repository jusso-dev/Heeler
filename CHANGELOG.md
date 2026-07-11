# Changelog

All notable changes to Heeler are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-07-11

Initial release.

### Added

- NTPv4/NTPv3 unicast UDP server (mode 3 client requests only), IPv4 and
  IPv6, protocol-correct 48-byte server responses with strict T1/T2/T3
  semantics.
- `heeler-core` protocol crate: explicit big-endian packet parser and
  encoder, 64-bit NTP timestamp type with 1900/1970 epoch conversion and
  pivot-based era unfolding across the 2036 rollover, signed/unsigned
  16.16 fixed-point root fields, typed leap/mode/version/stratum,
  reference identifiers, request validation policy, response and
  Kiss-o'-Death builders, and a `ClockSource` trait with system and mock
  implementations.
- System clock source with monotonic cross-checked jump detection;
  configurable thresholds mark the server unsynchronised (leap 3,
  stratum 16) after implausible wall-clock movement.
- Security controls: longest-prefix CIDR allow/deny lists (deny wins
  ties), bounded per-client + global token-bucket rate limiting with
  fail-closed table limits and KoD throttling, strict public-bind
  acknowledgement, loopback-only defaults.
- Configuration via TOML, `HEELER_*` environment variables, and CLI flags
  with full startup validation; documented example config kept in sync
  with built-in defaults by test.
- CLI: `serve`, `check-config`, `print-default-config`, `inspect-packet`,
  `query` (diagnostic client with delay/offset calculation), `version`,
  `bench`.
- Observability: structured pretty/compact/JSON logging and an optional
  loopback Prometheus endpoint with fixed, unlabelled metrics.
- Unix privilege drop (bind → setgroups → setgid → setuid → verify) run
  single-threaded before the async runtime; graceful SIGINT/SIGTERM
  shutdown with final counters.
- Tests: unit, golden-packet, property-based (proptest), integration
  (live server on ephemeral ports incl. hostile input and 32-client
  concurrency), and a libFuzzer target covering parse, validate, respond,
  and era unfolding.
- Packaging: hardened systemd unit, distroless non-root Docker image,
  Debian skeleton, release/test scripts, CI/security/release workflows.

[Unreleased]: https://github.com/jusso-dev/Heeler/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jusso-dev/Heeler/releases/tag/v0.1.0
