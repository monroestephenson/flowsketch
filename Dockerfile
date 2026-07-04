# syntax=docker/dockerfile:1

FROM rust:1.82-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p flowsketch-cli

FROM debian:bookworm-slim
RUN useradd --system --uid 65532 --home /nonexistent --shell /usr/sbin/nologin flowsketch \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/flowsketch /usr/local/bin/flowsketch
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/flowsketch"]
