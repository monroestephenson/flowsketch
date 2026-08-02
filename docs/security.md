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
- Live AF_PACKET and normalized eBPF timestamps are accepted only within five
  minutes of realtime. Outliers are dropped and counted before event-time
  windowing, so one corrupt record cannot fast-forward all runtime shards.
- Group labels can still contain sensitive metadata such as IP addresses.
  Use `export.maxSeries`, query filters, and downstream retention controls
  accordingly.

## HTTP exposure

- The application-level default listen address is `127.0.0.1:9464`. The
  Kubernetes assets bind agent and gateway servers to `0.0.0.0` so probes,
  Prometheus, and agents can reach them. Because agents use `hostNetwork`,
  this also makes the agent port reachable on the node network unless a
  firewall, CNI policy, or authenticated node-local proxy restricts it.
- The agent HTTP server exposes read-only endpoints:
  `/metrics`, `/healthz`, `/readyz`, and `/v1/queries`.
- The gateway HTTP server exposes read-only endpoints plus
  `POST /v1/snapshots` for agent snapshot pushes.
- The built-in HTTP servers do not implement TLS, authentication, or remote
  configuration. Bind them to localhost, a pod-local interface, or a
  protected management network. Put a reverse proxy or service mesh in
  front if remote authenticated access is required.
- Authorize agent identities only to `POST /v1/snapshots`, monitoring
  identities only to `GET /metrics`, and probes/operators only to the health
  and inventory endpoints. Kubernetes NetworkPolicy cannot authorize HTTP
  methods; use a layer-7 mesh/proxy where those identities share a port.
- Do not expose either HTTP server through a public LoadBalancer, ingress, or
  node firewall rule. Validate host-network behavior for the selected CNI and
  service mesh; a node-local proxy is the safer boundary when sidecar
  interception does not cover host-network traffic.
- HTTP request handling is bounded: connection count, request-line size,
  header size, body size where request bodies exist, and read/write
  timeouts are capped.

## Capture privileges

- Offline pcap replay does not need elevated privileges.
- Linux AF_PACKET live capture requires CAP_NET_RAW or root. Prefer granting
  only CAP_NET_RAW to the agent binary/container instead of running a broad
  privileged process.
- The production image keeps the ordinary CLI unprivileged and ships three
  dedicated agent copies with exact file capabilities: AF_PACKET (NET_RAW),
  eBPF-only (BPF, NET_ADMIN, PERFMON), and explicit eBPF fallback (those plus
  NET_RAW). Kubernetes selects one inside a matching drop-all bounding set.
  The agent must allow the exec-time capability transition; the gateway uses
  `no_new_privs` and has no file-capability entrypoint.
- macOS and other non-Linux platforms support pcap replay for development
  and offline analysis. AF_PACKET live capture returns a clear Linux-only
  error.

## Exporters

- Prometheus output is text exposition over the agent HTTP endpoint. Series
  count is capped per query and dropped-series counts are exported.
- OTLP export is OTLP/HTTP JSON over plain `http://` only in the current
  release. The
  intended topology is agent-to-local-collector. Use the collector for TLS,
  authentication, tenancy, and internet egress policy.
- OTLP requests have bounded endpoint length, request body size, connect
  timeout, response read size, and retry count.
- Gateway snapshot pushes are plain `http://` in the current release and are intended for
  agent-to-gateway traffic on a trusted cluster network. Push requests have
  bounded endpoint length, request body size, connect timeout, response
  read size, and retry count.

## Snapshots

- FSK1 version 2 snapshots include compatibility metadata and a checksum to
  detect accidental corruption. Hash/snapshot version changes fail closed and
  require a coordinated agent/gateway rollout.
- The checksum is not a cryptographic authenticity guarantee. Treat
  snapshots as trusted operational artifacts; do not merge snapshots from
  untrusted sources.

## Operational assumptions

- Run the agent with least privilege.
- Keep query files under normal configuration-management controls.
- Do not expose the agent HTTP port directly to untrusted networks.
- Store remote-backend credentials and private keys in a collector/proxy or
  secret store, not in FlowSketch query ConfigMaps, CLI arguments, dashboards,
  or committed values files.
- Test certificate issuance, expiry monitoring, rotation, and revocation for
  every proxy/mesh/collector hop. FlowSketch cannot detect an authentication
  downgrade outside its own plaintext endpoint.
- Validate alert thresholds against local traffic shape, especially for
  heuristic measures such as entropy.

The concrete trust-boundary, incident-response, restart, and upgrade
procedures are in `docs/runbook.md`.
