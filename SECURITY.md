# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security
Advisories ("Report a vulnerability" on the repository's Security tab)
rather than public issues. Reports are acknowledged as quickly as
possible; please allow a reasonable window for a fix before disclosure.

## Threat model

Heeler answers unauthenticated UDP datagrams from potentially hostile
networks. The threats it is designed to resist, and how:

| Threat | Mitigation |
|---|---|
| UDP reflection / amplification | Responses are exactly 48 bytes and never larger than a valid request; no monlist, no control (mode 6), no private (mode 7), no variable-length diagnostics; non-client modes are never answered; Kiss-o'-Death is 48 bytes, per-client throttled, and disabled entirely for global overload |
| Packet floods | Per-client and global token buckets on monotonic time; global exhaustion is a silent drop |
| Rate-limiter memory exhaustion | Hard cap on tracked clients, TTL expiry, at most one forced eviction scan per second, fail-closed when full — an attacker cannot grow state without bound |
| Malformed input | Total, allocation-free parser over untrusted bytes; length checked first; oversized datagrams dropped; property tests and fuzzing assert the parser never panics; `#![forbid(unsafe_code)]` in the protocol crate — no unsafe byte casting anywhere |
| Integer/timestamp overflow | Checked/widened (128-bit) arithmetic in all time conversions; times before 1900 and unrepresentable values are errors, not panics |
| Era ambiguity | Wire timestamps documented as era-ambiguous; internal representation is unambiguous; unfolding is explicit, pivot-based, and tested across the 2036 rollover |
| Spoofed source addresses | UDP sources are unauthenticated by nature: Heeler sends at most one small response per request, rate-limits per claimed source, and fails closed under state pressure; deploy behind a firewall for stronger guarantees |
| Client-data injection | The only client-controlled bytes in a response are the origin-timestamp echo required by the protocol; no other client field is copied into server state or responses |
| Public exposure by accident | Loopback-only defaults; strict mode refuses non-private binds without explicit acknowledgement; prominent warnings otherwise |
| Log flooding | Per-packet events log at trace/debug only; hostile traffic is counted, not printed |
| Metric cardinality attacks | No per-client labels; the metric set is fixed; the metrics listener binds loopback by default and answers only `GET /metrics` |
| Privilege retention | Recommended deployments never run as root (capabilities/systemd/high port); optional bind-then-drop verifies root cannot be regained and aborts otherwise |
| Expensive parsing DoS | Parsing is constant-time-ish over a fixed 48-byte layout, no allocation proportional to input; access control and rate limiting run before parsing |
| Unexpected extension fields | Trailing bytes after the base packet are rejected by default (optionally ignored, never interpreted) |
| Clock jumps | Wall clock cross-checked against the monotonic clock; jumps are logged, counted, and (by default) flip responses to leap 3 / stratum 16 |

## Security defaults

- allow list: loopback only; default action deny
- rate limiting: enabled
- metrics: disabled; loopback-bound when enabled
- no control protocol, no remote administration, ever
- strict public-bind refusal without acknowledgement
- silent drop for malformed and policy-refused traffic
- no dynamic memory sized by packet contents
- privilege drop verified irreversible when used

## Out of scope for version 1

Cryptographic authentication (NTS, symmetric-key MACs) is not implemented;
Heeler cannot protect clients from an on-path attacker who rewrites
packets. Do not use unauthenticated NTP across untrusted networks for
security-critical time.

## Hardening checklist for operators

1. Keep the host clock disciplined by a trusted source.
2. Firewall UDP 123 to intended client networks (Heeler's `[access]` is
   defence in depth, not the perimeter).
3. Run without root: `setcap cap_net_bind_service=+ep` or the provided
   hardened systemd unit.
4. Leave rate limiting on; size `max_client_entries` to your client count.
5. Keep metrics on loopback or a management network.
6. Watch `heeler_clock_jumps_total` and `heeler_clock_synchronised`.
