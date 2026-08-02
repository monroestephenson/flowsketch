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
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin
COPY --from=builder /src/target/release/flowsketch /usr/local/bin/flowsketch
COPY --from=builder /out/flowsketch_tc.bpf.o /usr/lib/flowsketch/flowsketch_tc.bpf.o
RUN install -d -m 0755 /usr/local/libexec \
    && install -m 0755 /usr/local/bin/flowsketch /usr/local/libexec/flowsketch-agent-afpacket \
    && install -m 0755 /usr/local/bin/flowsketch /usr/local/libexec/flowsketch-agent-ebpf \
    && install -m 0755 /usr/local/bin/flowsketch /usr/local/libexec/flowsketch-agent-ebpf-fallback \
    && setcap cap_net_raw=ep /usr/local/libexec/flowsketch-agent-afpacket \
    && setcap cap_bpf,cap_net_admin,cap_perfmon=ep /usr/local/libexec/flowsketch-agent-ebpf \
    && setcap cap_bpf,cap_net_admin,cap_perfmon,cap_net_raw=ep /usr/local/libexec/flowsketch-agent-ebpf-fallback \
    && test "$(getcap /usr/local/libexec/flowsketch-agent-afpacket)" = \
       "/usr/local/libexec/flowsketch-agent-afpacket cap_net_raw=ep" \
    && getcap /usr/local/libexec/flowsketch-agent-ebpf | grep -q 'cap_net_admin,cap_perfmon,cap_bpf=ep' \
    && getcap /usr/local/libexec/flowsketch-agent-ebpf-fallback | grep -q 'cap_net_admin,cap_net_raw,cap_perfmon,cap_bpf=ep' \
    && apt-get purge -y libcap2-bin \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/flowsketch"]
