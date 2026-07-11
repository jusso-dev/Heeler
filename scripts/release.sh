#!/usr/bin/env bash
# Build a release binary for the current host and produce checksums plus a
# reproducible release-notes stub. CI (release.yml) does the multi-target
# equivalent on tags.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(cargo metadata --format-version 1 --no-deps |
    sed -n 's/.*"name":"heeler-server","version":"\([^"]*\)".*/\1/p')
TARGET=$(rustc -vV | sed -n 's/^host: //p')
OUT="dist/heeler-${VERSION}-${TARGET}"

echo "==> building heeler ${VERSION} for ${TARGET}"
cargo build --release --locked -p heeler-server

mkdir -p "${OUT}"
cp target/release/heeler "${OUT}/"
cp README.md LICENSE SECURITY.md CHANGELOG.md config/heeler.example.toml "${OUT}/"

tar -C dist -czf "${OUT}.tar.gz" "$(basename "${OUT}")"

(cd dist && sha256sum "$(basename "${OUT}").tar.gz" > "$(basename "${OUT}").tar.gz.sha256")

cat > "dist/RELEASE_NOTES-${VERSION}.md" <<EOF
# heeler ${VERSION}

Built from commit $(git rev-parse HEAD) on ${TARGET} with $(rustc --version).

## Checksums

\`\`\`
$(cat "${OUT}.tar.gz.sha256")
\`\`\`

See CHANGELOG.md for the changes in this release.
EOF

echo "==> artifacts in dist/"
ls -l dist/
