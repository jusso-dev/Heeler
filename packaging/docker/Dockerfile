# Multi-stage build: Rust builder, distroless runtime with no shell or
# package manager, running as the non-root "nonroot" user (uid 65532).

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY config ./config
RUN cargo build --release --locked -p heeler-server \
    && strip target/release/heeler || true

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/heeler /usr/local/bin/heeler
COPY packaging/docker/heeler.toml /etc/heeler/heeler.toml

# The container listens on the unprivileged port 11123 so it can run fully
# non-root with all capabilities dropped; map host UDP 123 onto it:
#
#   docker run --read-only --cap-drop=ALL \
#     -p 123:11123/udp \
#     -v ./heeler.toml:/etc/heeler/heeler.toml:ro \
#     heeler:latest
#
# To bind port 123 *inside* the container instead, run the container
# process as root with only the needed capabilities and let Heeler drop to
# uid 65532 itself (see [security] in the config):
#
#   docker run --read-only --user 0 \
#     --cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=SETUID --cap-add=SETGID \
#     -p 123:123/udp -v ./heeler.toml:/etc/heeler/heeler.toml:ro heeler:latest
#
# NTP is UDP: never publish a TCP mapping for it.
EXPOSE 11123/udp

USER nonroot
ENTRYPOINT ["/usr/local/bin/heeler"]
CMD ["serve", "--config", "/etc/heeler/heeler.toml"]
