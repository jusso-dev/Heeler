# Contributing to Heeler

Thanks for helping build a small, serious time server.

## Ground rules

- **Correctness first.** NTP wire fields are big-endian; the base packet
  is 48 bytes; T2 and T3 are separate measurements; monotonic time for
  intervals, wall time only inside packets. When in doubt, read the
  "Important correctness rules" the project was built against (README
  architecture section and module docs) and RFC 5905.
- **No panics on network input.** The parser and everything downstream
  must be total over arbitrary bytes. Add a property test or fuzz case
  with any parser change.
- **No unsafe** outside `heeler-server/src/privilege.rs`, which is the
  single documented exception. `heeler-core` is `#![forbid(unsafe_code)]`.
- **No new dependencies without justification.** Every crate must earn its
  place and be added to the README dependency table.
- **No hidden network access, telemetry, or shelling out** — especially
  not in the packet path.
- Library code returns typed errors; only the binary boundary uses
  `anyhow`; no `unwrap`/`expect`/`panic!` outside tests.

## Workflow

1. Fork and branch.
2. `./scripts/test.sh` must pass: rustfmt, clippy with `-D warnings`, all
   tests, and docs.
3. For protocol-visible changes, include golden bytes in tests (raw hex,
   parsed fields, expected response) — do not generate expectations with
   the code under test.
4. For behaviour changes, update `config/heeler.example.toml`, the README,
   and CHANGELOG.md.
5. Open a pull request describing the protocol reasoning, not just the
   code motion.

## Running the pieces

```sh
cargo test --workspace                     # everything
cargo test -p heeler-core                  # protocol layer only
cargo run -p heeler-server -- serve --bind 127.0.0.1:11123
cargo run -p heeler-server -- query 127.0.0.1:11123
cargo +nightly fuzz run parse_packet       # needs cargo-fuzz
```

## Commit style

Imperative subject line, body explaining *why*. Keep refactors and
behaviour changes in separate commits.
