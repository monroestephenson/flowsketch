# Security posture

FlowSketch is an observability agent for network metadata. It is not a
security boundary, packet firewall, TLS endpoint, SIEM, or secret store.

## Data handling

- Packet payloads are not parsed, retained, hashed, or exported.
- The pcap parser extracts L2/L3/L4 metadata only: addresses, ports,
  protocol, TCP flags, byte counts, packet counts, interface index, and
  timestamps.
- Query outputs are approximate aggregates. Raw packet records are not
  stored by the runtime.
- Group labels can still contain sensitive metadata such as IP addresses.
  Use `export.maxSeries`, query filters, and downstream retention controls
  accordingly.

## HTTP exposure

- The default listen address is `127.0.0.1:9464`.
- The agent HTTP server exposes read-only endpoints:
  `/metrics`, `/healthz`, `/readyz`, and `/v1/queries`.
- The gateway HTTP server exposes read-only endpoints plus
  `POST /v1/snapshots` for agent snapshot pushes.
- The built-in HTTP servers do not implement TLS, authentication, or remote
  configuration. Bind them to localhost, a pod-local interface, or a
  protected management network. Put a reverse proxy or service mesh in
  front if remote authenticated access is required.
- HTTP request handling is bounded: connection count, request-line size,
  header size, body size where request bodies exist, and read/write
  timeouts are capped.

## Capture privileges

- Offline pcap replay does not need elevated privileges.
- Linux AF_PACKET live capture requires CAP_NET_RAW or root. Prefer granting
  only CAP_NET_RAW to the agent binary/container instead of running a broad
  privileged process.
- macOS and other non-Linux platforms support pcap replay for development
  and offline analysis. AF_PACKET live capture returns a clear Linux-only
  error.

## Exporters

- Prometheus output is text exposition over the agent HTTP endpoint. Series
  count is capped per query and dropped-series counts are exported.
- OTLP export is OTLP/HTTP JSON over plain `http://` only in v0. The
  intended topology is agent-to-local-collector. Use the collector for TLS,
  authentication, tenancy, and internet egress policy.
- OTLP requests have bounded endpoint length, request body size, connect
  timeout, response read size, and retry count.
- Gateway snapshot pushes are plain `http://` in v0 and are intended for
  agent-to-gateway traffic on a trusted cluster network. Push requests have
  bounded endpoint length, request body size, connect timeout, response
  read size, and retry count.

## Snapshots

- FSK1 snapshots include compatibility metadata and a checksum to detect
  accidental corruption.
- The checksum is not a cryptographic authenticity guarantee. Treat
  snapshots as trusted operational artifacts; do not merge snapshots from
  untrusted sources.

## Operational assumptions

- Run the agent with least privilege.
- Keep query files under normal configuration-management controls.
- Do not expose the agent HTTP port directly to untrusted networks.
- Validate alert thresholds against local traffic shape, especially for
  heuristic measures such as entropy.
