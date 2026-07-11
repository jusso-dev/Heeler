#!/usr/bin/env bash
# Full local verification: formatting, lints, tests, docs.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo clippy (deny warnings)"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> cargo test"
cargo test --workspace --all-features

echo "==> cargo doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "==> fuzz target compiles"
(cd fuzz && cargo check)

if command -v cargo-audit >/dev/null 2>&1; then
    echo "==> cargo audit"
    cargo audit
else
    echo "==> cargo audit skipped (install with: cargo install cargo-audit)"
fi

if command -v cargo-deny >/dev/null 2>&1; then
    echo "==> cargo deny"
    cargo deny check
else
    echo "==> cargo deny skipped (install with: cargo install cargo-deny)"
fi

echo "All checks passed."
