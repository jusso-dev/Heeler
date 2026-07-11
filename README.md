# Heeler

A lightweight, secure, auditable NTP server written in Rust.

Heeler is a small NTPv4-compatible unicast time server for private
networks, homelabs, edge appliances, disconnected and sovereign
environments, internal cloud networks, labs, embedded Linux systems, and
containerised infrastructure — anywhere an organisation wants a simple
internal source of network time that one engineer can read, audit, test,
and safely deploy.

> **Heeler serves the host system clock. It does not make an inaccurate
> host clock accurate.** Keep the host synchronised (chrony, ntpd,
> systemd-timesyncd, PTP, a hypervisor clock, …) if downstream clients need
> accurate time. Heeler never adjusts, steps, or disciplines the system
> clock, and it never contacts external time services.

Deploy Heeler behind a firewall and expose it only to intended clients.
The default configuration answers loopback only; serving a wider network
is an explicit operator decision.

## What Heeler is

- an NTPv4/NTPv3 **unicast server** (RFC 5905 subset) over UDP port 123;
- IPv4 and IPv6;
- protocol-correct 48-byte responses with careful T1/T2/T3 semantics;
- era-aware timestamp handling (documented and tested across the 2036
  rollover);
- defensive by default: CIDR access control, bounded per-client and global
  rate limiting, silent handling of malformed traffic, optional
  Kiss-o'-Death (`RATE`, `DENY`), and responses never larger than requests;
- observable: structured logs (pretty/compact/JSON) and an optional
  Prometheus endpoint;
- deployable without permanent root: capabilities, systemd, high ports, or
  bind-then-drop privileges.

## What Heeler is not

Version 1 deliberately does **not** implement: peer/symmetric modes,
broadcast, manycast/multicast, clock discipline or kernel PLL control,
leap smearing, upstream synchronisation, NTS, Autokey, symmetric-key MACs,
GPS/PPS/PTP reference clocks, control (mode 6) or private (mode 7)
queries, remote administration, or any monlist-style diagnostics. The
crate layout keeps the packet and clock layers independent so these can be
added without rewriting the server.

## Supported requests

| Property | Served |
|---|---|
| Modes | mode 3 (client) only; everything else is ignored |
| Versions | NTPv3 and NTPv4 (response mirrors the request version) |
| Packet size | 48-byte base packet; trailing bytes rejected by default, optionally ignored |
| Transports | unicast UDP, IPv4 + IPv6 |

## Accuracy, honestly

Heeler timestamps requests in user space: receive timestamps are captured
immediately after the datagram arrives and transmit timestamps immediately
before the send syscall, but both include scheduling and syscall latency,
and neither reflects hardware transmission time. Real-world accuracy
depends on host clock quality and synchronisation, kernel scheduling,
network latency and route asymmetry, virtualisation, CPU load, and power
management. On a quiet LAN, millisecond-level client synchronisation is
typical; Heeler makes no stronger claim. Kernel/hardware timestamping is a
future extension point.

## Installation

Prebuilt binaries are attached to releases (with SHA-256 checksums). From
source:

```sh
git clone https://github.com/jusso-dev/Heeler
cd Heeler
cargo build --release          # requires stable Rust 1.82+
./target/release/heeler version
```

## Quick start

```sh
# Serve loopback on an unprivileged port and query yourself:
./target/release/heeler serve --bind 127.0.0.1:11123 &
./target/release/heeler query 127.0.0.1:11123
```

The query subcommand is a built-in diagnostic client: it prints the raw
and interpreted T1-T4 timestamps, the round-trip delay
`(T4 - T1) - (T3 - T2)`, and the clock offset
`((T2 - T1) + (T3 - T4)) / 2`. It never modifies the local clock.

Other subcommands:

```sh
heeler check-config --config /etc/heeler/heeler.toml   # validate and exit
heeler print-default-config                            # documented defaults
heeler inspect-packet 230006ec00…                      # decode hex packets
heeler bench                                           # CPU micro-benchmarks
heeler version
```

## Configuration

Precedence: **CLI flags > `HEELER_*` environment variables > TOML file >
built-in defaults.** Without `--config`, `/etc/heeler/heeler.toml` is used
when it exists. Every option, with its default value and documentation, is
in [`config/heeler.example.toml`](config/heeler.example.toml) (identical
to `heeler print-default-config`; a test keeps them in sync).

Environment overrides: `HEELER_BIND` (comma-separated),
`HEELER_LOG_LEVEL`, `HEELER_LOG_FORMAT`, `HEELER_STRATUM`,
`HEELER_REFERENCE_ID`, `HEELER_METRICS_ENABLED`, `HEELER_METRICS_BIND`,
`HEELER_RATE_LIMIT_ENABLED`, `HEELER_PUBLIC_BIND_ACKNOWLEDGED`.

Highlights:

- `protocol.stratum` defaults to **2** ("I serve a clock synchronised by
  something else"). Stratum describes distance from a reference clock, not
  inherent accuracy. Stratum 1 requires explicitly configuring a
  `reference_id` naming a real reference source (`GPS`, `PPS`, `LOCL`, …) —
  Heeler will not claim to be a primary server by default.
- `clock` cross-checks the wall clock against the monotonic clock; a jump
  beyond the thresholds marks the server unsynchronised (leap indicator 3,
  stratum 16) until restart.
- `access` uses longest-prefix matching; deny wins ties; the default
  action applies when nothing matches. Defaults allow loopback only.
- `rate_limit` is a per-client token bucket plus a global bucket, bounded
  in memory, using monotonic time.

### Public exposure warning

Binding a non-loopback, non-private address is refused by default
(`server.strict_public_bind = true`) until you set
`public_bind_acknowledged = true` (or pass `--public-bind-acknowledged`)
after restricting `[access]`. Even acknowledged public binds log a
prominent warning. NTP over UDP is a reflection-attack vector; Heeler's
responses never exceed 48 bytes and it implements no amplifying commands,
but exposure should still be a deliberate act.

## Serving real clients

```sh
# 1. Restrict access to your networks:
#    /etc/heeler/heeler.toml
#      [server]
#      bind = ["0.0.0.0:123", "[::]:123"]
#      public_bind_acknowledged = true
#      [access]
#      allow = ["10.0.0.0/8", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128"]

# 2. Give the binary the capability to bind port 123 without root:
sudo setcap cap_net_bind_service=+ep /usr/local/bin/heeler

# 3. Run as an ordinary user:
heeler serve --config /etc/heeler/heeler.toml
```

Alternatives: run under systemd (below, recommended), bind a high port
behind a firewall redirect, or start as root and let
`[security] drop_privileges` switch to an unprivileged user after binding
(bind → setgroups → setgid → setuid → verify root cannot be regained).
Privilege drop is implemented for Unix; on other platforms Heeler makes no
claim and the recommended deployment is an unprivileged high port.

Point clients at it:

```text
chrony:            server ntp.internal iburst
systemd-timesyncd: NTP=ntp.internal in /etc/systemd/timesyncd.conf
ntpd:              server ntp.internal iburst
busybox/embedded:  ntpd -p ntp.internal
macOS:             sntp ntp.internal
```

`ntpq -c rv` style control queries are refused by design (mode 6); use
`heeler query`, metrics, or logs instead.

## systemd deployment

A hardened unit is provided in
[`packaging/systemd/heeler.service`](packaging/systemd/heeler.service):
it runs Heeler directly as the `heeler` system user with only
`CAP_NET_BIND_SERVICE`, plus filesystem, namespace, and syscall
sandboxing.

```sh
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin heeler
sudo install -D -m 0644 config/heeler.example.toml /etc/heeler/heeler.toml
sudo install -m 0755 target/release/heeler /usr/local/bin/heeler
sudo install -m 0644 packaging/systemd/heeler.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now heeler
```

## Docker deployment

The image ([`packaging/docker/Dockerfile`](packaging/docker/Dockerfile))
is a multi-stage build onto distroless (no shell, no package manager),
running as the non-root `nonroot` user and listening on the unprivileged
port 11123 inside the container:

```sh
docker build -t heeler -f packaging/docker/Dockerfile .
docker run --read-only --cap-drop=ALL \
  -p 123:11123/udp \
  -v ./heeler.toml:/etc/heeler/heeler.toml:ro \
  heeler
```

NTP is UDP — never publish a TCP mapping for it. To bind port 123 inside
the container instead, see the comments in the Dockerfile
(`--cap-add=NET_BIND_SERVICE,SETUID,SETGID` with Heeler's own privilege
drop). Health check: probe with `heeler query` from a sidecar or use the
metrics endpoint; the distroless image intentionally contains no shell for
`HEALTHCHECK` commands.

## Firewall examples

```sh
# nftables: allow NTP from the LAN only
nft add rule inet filter input ip saddr 10.0.0.0/8 udp dport 123 accept
nft add rule inet filter input udp dport 123 drop

# iptables
iptables -A INPUT -s 10.0.0.0/8 -p udp --dport 123 -j ACCEPT
iptables -A INPUT -p udp --dport 123 -j DROP
```

Heeler's `[access]` list is defence in depth, not a firewall replacement.

## Metrics

Enable `[metrics]` (loopback-bound by default) and scrape
`http://127.0.0.1:9180/metrics`. Counters include requests, responses,
drops, malformed packets, unsupported versions/modes, rate-limited and
access-denied requests, KoD responses, socket and clock errors, clock
jumps, a synchronised gauge, active rate-limiter entries, uptime, and a
response-build-duration histogram. Metrics carry **no per-client labels**
(bounded cardinality by design).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `binding UDP sockets … permission denied` | port 123 without privileges — use setcap, systemd, or a high port |
| starts then exits: `refusing to bind public address` | acknowledge and restrict access, or bind a private address |
| starts then exits: `user "heeler" not found` | create the user, use a numeric UID, or set `security.drop_privileges = false` |
| client gets no answer | `[access]` denies it (check `heeler_access_denied_total`), rate limiting, or a firewall |
| responses show leap 3 / stratum 16 | the wall clock jumped (see logs); restart after fixing host time sync |
| `heeler query` times out against ntpd/chrony | some servers ignore unsynchronised or restricted clients |

## Architecture

```text
UDP Socket
    |
    v
Datagram Size Validation
    |
    v
Access Control          (longest-prefix CIDR, deny wins ties)
    |
    v
Rate Limiter            (per-IP + global token buckets, monotonic time)
    |
    v
Packet Parser           (48-byte base packet, explicit big-endian fields)
    |
    v
Protocol Validation     (mode 3 only, versions 3-4, policy checks)
    |
    v
Clock Source            (system clock; trait for future GPS/PPS/upstream)
    |
    v
Response Builder        (T1 echo, T2 from receive, stratum/leap policy)
    |
    v
Packet Encoder
    |
    v
UDP Send                (T3 stamped immediately before send)
```

Two crates separate concerns:

- **`heeler-core`** — wire protocol, timestamps and era handling, clock
  sources, validation, response building. No async runtime, no sockets,
  `#![forbid(unsafe_code)]`; fully testable and fuzzable in isolation.
- **`heeler-server`** — Tokio UDP runtime (one receive loop per socket,
  requests processed inline: no per-packet task spawning), configuration,
  access control, rate limiting, metrics, privilege drop (the one small,
  documented `unsafe` module, Unix-only), shutdown, and the CLI.

The packet path never performs DNS lookups, filesystem access, shell
commands, or allocation proportional to untrusted input.

### Timestamps and eras

NTP timestamps are 64-bit fixed point (32-bit seconds since 1900-01-01,
32-bit fraction in 2⁻³² s units); the Unix↔NTP offset is 2,208,988,800
seconds. The 32-bit seconds field wraps in 2036, so wire timestamps are
era-ambiguous by definition. Internally Heeler uses a signed 128-bit
nanosecond count since 1900; encoding emits the low 32 bits of the second
count and decoding unfolds against a pivot near the current time
(unambiguous within ±68 years). Fraction conversions use 128-bit
integer arithmetic and truncate toward zero (< 1 ns round-trip error);
both directions are property-tested across the rollover.

## Development

```sh
cargo test --workspace          # unit + property + integration tests
./scripts/test.sh               # fmt, clippy -D warnings, tests, docs, audit
cargo run -p heeler-server -- serve --bind 127.0.0.1:11123
```

Linux is the primary platform; the workspace also compiles and runs on
macOS for development (privilege drop uses the same Unix APIs).

Dependencies and why they exist:

| Crate | Purpose |
|---|---|
| `tokio` | async UDP sockets, timers, signals |
| `clap` | command-line parsing |
| `serde` + `toml` | configuration file parsing |
| `tracing`, `tracing-subscriber` | structured logging |
| `thiserror` | typed library errors |
| `anyhow` | error context at the binary boundary only |
| `socket2` | socket options before bind (buffers, v6-only, reuseaddr) |
| `ipnet` | CIDR parsing/matching for access control |
| `libc` (Unix) | privilege-drop syscalls (isolated `unsafe` module) |
| `proptest` (dev) | property-based tests |
| `libfuzzer-sys` (fuzz) | fuzzing harness |

No NTP protocol crate, no external time API, no telemetry, no network
access outside serving NTP and the optional loopback metrics listener.

## Testing

- **Unit tests** cover bit packing, byte order, fixed point, epoch/era
  conversion, reference IDs, stratum validation, KoD, access precedence,
  and rate-limiter refill/expiry/bounds.
- **Golden packet tests** parse and re-encode hand-constructed byte arrays.
- **Property tests** (proptest) round-trip arbitrary packets and
  timestamps and verify era unfolding around 2036.
- **Integration tests** run a real server on ephemeral loopback ports:
  v3/v4, IPv6, malformed/oversized/garbage input, KoD, access control,
  rate limiting, unsynchronised and clock-failure behaviour, graceful
  shutdown, metrics, and a 32-client concurrency test asserting per-request
  origin-timestamp integrity.
- **Fuzzing**: `cargo +nightly fuzz run parse_packet` exercises parsing,
  validation, response building, and era unfolding; the parser must never
  panic. CI runs a short fuzz pass on every push.

## Roadmap

Planned behind the existing `ClockSource` and packet layers: kernel
receive/transmit timestamping, upstream NTP client mode with source
selection and filtering, optional system-clock discipline, GPS/GNSS/PPS
reference clocks, NTS, symmetric-key authentication, leap-second files,
systemd socket activation, and Windows service support.

## Licence

MIT — see [LICENSE](LICENSE).
