# syntax=docker/dockerfile:1

FROM rust:1.85-bookworm AS builder
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN scripts/build-ebpf.sh /out/flowsketch_tc.bpf.o \
    && cargo build --locked --release -p flowsketch-cli

FROM debian:bookworm-slim
RUN useradd --system --uid 65532 --home /nonexistent --shell /usr/sbin/nologin flowsketch \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/flowsketch /usr/local/bin/flowsketch
COPY --from=builder /out/flowsketch_tc.bpf.o /usr/lib/flowsketch/flowsketch_tc.bpf.o
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/flowsketch"]
