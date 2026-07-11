# FlowSketch

FlowSketch is a Rust runtime for approximate network telemetry. It answers
high-cardinality questions such as top talkers, scanner fan-out, distinct
destinations, entropy shifts, packet-size quantiles, and traffic-matrix changes
with bounded memory and explicit error contracts.

The goal is not to be another sketch library. The goal is to make streaming
and sketching algorithms usable as production network observability
infrastructure: operators declare a network question, FlowSketch plans a
bounded sketch, runs it near traffic, and exports normal Prometheus or
OpenTelemetry signals.

## Current Status

FlowSketch is a credible v0 with several production-prep pieces already in
place. It is not yet a broadly production-ready 100 Gb/s collector.

Implemented today:

| Area | Status |
| ---- | ------ |
| Core sketches | Count-Min, CountSketch, HyperLogLog, HLLMap, SpaceSaving, Misra-Gries, KLL, exact baseline |
| Query model | YAML queries, logical IR, physical plans, memory estimates, explain output |
| Runtime | Windowing, filtering, merge-correct parallel shards, grouped estimates, snapshot serialization |
| CLI | `synth`, `replay`, `bench`, `explain`, `validate`, `merge-snapshots`, `agent`, `gateway` |
| Sources | Synthetic pcap generation, pcap replay, Linux AF_PACKET live capture with socket-drop accounting |
| Exports | Prometheus text output, HTTP `/metrics`, OTLP/HTTP+JSON metrics export |
| Distributed merge | Agents can push FSK1 snapshots to a gateway, which validates and merges compatible windows |
| Deployment prep | Dockerfile, systemd, Kubernetes manifests, Prometheus Operator monitors/alerts, cross-platform CI |
| eBPF prep | Versioned 56-byte ring-buffer ABI with safe decoding plus collector roadmap |

Not implemented yet:

| Gap | Why it matters |
| --- | -------------- |
| eBPF tc/XDP collector | Needed for credible Linux production packet collection |
| Parallel RX-queue ingest | Runtime shards exist; capture still needs direct RSS/RX-queue fan-out for 25/40/100 Gb/s |
| eBPF ring/drop accounting | AF_PACKET kernel and userspace drops are counted; the future eBPF path needs equivalent counters |
| Kubernetes CRD/operator/Helm chart | Needed for normal platform-team adoption |
| Kubernetes metadata enrichment | Needed for namespace, pod, service, and workload queries |
| Gateway HA/sharding | The gateway is currently an in-memory merge point |
| Real 100 Gb/s validation | Current benchmarks are local projections, not live NIC proof |

Most recent full code validation before this README-only rewrite:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
kubectl kustomize deploy/kubernetes
```

The workspace test suite currently has 149 passing tests.

## Live Capture Today

FlowSketch currently has two agent source modes:

| Source | Where it works | What it proves |
| ------ | -------------- | -------------- |
| `pcap` | macOS, Linux, CI, local demos | runtime correctness against repeatable packet traces |
| `af_packet` | Linux only, needs root or `CAP_NET_RAW` | live packets can be captured from a Linux interface and fed into the runtime |

The live Linux path is functional but early. It uses a simple AF_PACKET raw
socket, parses Ethernet/IP/TCP/UDP headers, and pushes `FlowEvent`s into the
same merge-correct sharded sketch runtime used by replay. It reports both
AF_PACKET socket drops and userspace channel drops. It does not yet use
PACKET_MMAP/TPACKET, eBPF, XDP, AF_XDP, or direct RSS receive-queue ingestion.

GitHub Actions can run a true live functional test by creating a veth pair,
running the agent on one side with `source.kind: af_packet`, generating packets
from a network namespace on the other side, and asserting that the agent's
Prometheus counters increase. That proves the Linux live capture path works.
It does not prove 10 Gb/s line rate because GitHub-hosted runners do not expose
a dedicated 10G NIC or stable packet generator.

For local Linux VMs, the same smoke test can be run with:

```bash
cargo build --release -p flowsketch-cli
bash scripts/linux-afpacket-live-smoke.sh target/release/flowsketch
```

## Current Performance

The current benchmark baseline is recorded in
[`benchmarks/current-results.md`](benchmarks/current-results.md).

Measured on a local Mac release build:

| Path | Result |
| ---- | ------ |
| Count-Min hot loop | 19.26M updates/s/core |
| Projected L3 capacity for 1250-byte packets | 192.61 Gb/s/core |
| pcap parse + runtime + one query | 1.81M events/s/core |
| Projected L3 capacity on the generated trace | 9.13 Gb/s/core |
| Projected cores for 100 Gb/s on that trace shape | 10.95 cores |
| Merge-correct 8-shard runtime, 100G-normalized event time | 10.87M events/s median |
| Projected aggregate capacity for that sharded runtime | 54.99 Gb/s |
| GitHub Linux single-core projection | 12.10 Gb/s at 631.8-byte average packets |

Interpretation:

- The sketch update loop is fast enough that it is not the current 100 Gb/s
  blocker for large packets.
- The local single-stream path now passes the M3 10 Gb/s projection within a
  two-core budget, but it does not sustain 10 Gb/s on one core in this run.
- Merge-correct runtime sharding is implemented. Shards share an event-time
  watermark and merge window states before export, so parallel results do not
  duplicate or undercount windows.
- The balanced 8-shard runtime reaches a 54.99 Gb/s median projection on this host.
  Serial pcap parsing/dispatch and direct RX-queue ingestion remain blockers.
- Real 100 Gb/s networking is packet-rate dominated. At roughly 632-byte L3
  packets, 100 Gb/s is about 19.8M packets/s. At minimum Ethernet frame size,
  line rate is roughly 148.8M packets/s on the wire.
- FlowSketch needs eBPF/XDP or DPDK-style ingestion, receive-queue sharding,
  CPU pinning, drop counters, and live replay validation before making a real
  100 Gb/s claim.

Run the benchmark sweep:

```bash
cargo build --release -p flowsketch-cli

target/release/flowsketch bench \
  --algo count-min \
  --events 5000000 \
  --keys 100000 \
  --dist zipf \
  --profile all \
  --avg-packet-bytes 1250
```

Run the parser/runtime benchmark:

```bash
target/release/flowsketch synth \
  --out /tmp/flowsketch-bench.pcap \
  --packets 200000 \
  --scanners 2 \
  --heavy-talkers 3 \
  --duration-secs 120 \
  --seed 77

target/release/flowsketch bench \
  --trace /tmp/flowsketch-bench.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile all
```

Measure the merge-correct runtime with 100G event-time normalization:

```bash
target/release/flowsketch bench \
  --trace /tmp/flowsketch-bench.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile 100g \
  --runtime-shards 8 \
  --runtime-shard-strategy round-robin \
  --normalize-line-rate-gbps 100
```

`flow` is the default shard strategy and models normal directional RSS
affinity. `round-robin` is valid because sketch states are mergeable and is
useful when a few elephant flows would overload one shard. Timestamp
normalization changes window-advance frequency to match the candidate rate;
it does not include live capture or prove NIC line rate.

Gate a 10 Gb/s projection against a CPU budget:

```bash
target/release/flowsketch bench \
  --trace /tmp/flowsketch-bench.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile 10g \
  --core-budget 2
```

This is a projection gate for the measured trace path. It is useful for CI and
regression tracking, but it is not a substitute for live Linux NIC validation.

## Quick Start

Build the workspace:

```bash
cargo build --release
```

Generate a synthetic trace:

```bash
target/release/flowsketch synth \
  --out demo.pcap \
  --packets 200000
```

Explain a query:

```bash
target/release/flowsketch explain examples/queries/suspected-scanners.yaml
```

Replay the trace against several queries:

```bash
target/release/flowsketch replay demo.pcap \
  --query examples/queries/top-talkers.yaml \
  --query examples/queries/suspected-scanners.yaml
```

Serve a local agent from a config file:

```bash
target/release/flowsketch agent --config examples/agent.yaml
```

Run a gateway that receives agent snapshot pushes:

```bash
target/release/flowsketch gateway --config examples/gateway.yaml
```

## What FlowSketch Is

FlowSketch is an approximate network telemetry agent and runtime. It is meant
for questions where exact per-flow storage is too expensive, but where bounded
error and bounded memory are acceptable:

- top source/destination pairs by bytes or packets
- distinct destinations per source
- scanner and fan-out detection
- source entropy during DDoS-like shifts
- packet-size or flow-size quantiles
- approximate service or namespace traffic matrices
- change detection over adjacent windows

It should feel operationally familiar to teams that already use the
OpenTelemetry Collector, Prometheus exporters, Grafana Alloy, Datadog Agent,
Cilium/Hubble, or node-local infrastructure agents.

Algorithmically, it is based on streaming and sketching techniques: Count-Min,
CountSketch, HyperLogLog, heavy-hitter sketches, quantile sketches, and related
mergeable data structures.

## What It Is Not

| Not this | Reason |
| -------- | ------ |
| A generic sketch library | Apache DataSketches and similar projects already cover that space well |
| A packet sniffer | tcpdump, Wireshark, and pcap tools already exist |
| A Cilium replacement | Cilium/Hubble provide exact and near-exact Kubernetes flow visibility |
| A SIEM | Datadog, Splunk, Elastic, CrowdStrike, and others own that workflow |
| A database | FlowSketch should export estimates, not store all history itself |
| A new network stack | Adoption would be too hard |

The defensible framing is:

```text
existing packets / pcaps / flow logs
    -> FlowSketch collector
    -> sketch runtime and query planner
    -> approximate telemetry estimates
    -> Prometheus / OpenTelemetry / Kafka / ClickHouse / Datadog / Grafana
```

## Repository Layout

```text
flowsketch/
  crates/
    flowsketch-core/          common event, field, hash, estimate, snapshot traits
    flowsketch-algos/         Count-Min, CountSketch, HLL, HLLMap, KLL, heavy hitters
    flowsketch-ir/            logical and physical query IR
    flowsketch-planner/       sketch selection, memory estimates, error contracts
    flowsketch-runtime/       filtering, windowing, sketch execution, merges
    flowsketch-pcap/          pcap parser and writer
    flowsketch-prometheus/    Prometheus exposition
    flowsketch-otel/          OTLP metrics encoding and HTTP client
    flowsketch-agent/         host agent daemon
    flowsketch-gateway/       distributed snapshot merge gateway
    flowsketch-ebpf/          eBPF/userspace event contract
    flowsketch-cli/           command-line interface
  examples/
    agent.yaml
    gateway.yaml
    queries/*.yaml
  deploy/
    kubernetes/
    systemd/
  docs/
    query-language.md
    accuracy-contracts.md
    algorithm-notes.md
    operator-guide.md
    security.md
    production-readiness.md
    ebpf-roadmap.md
  benchmarks/
    README.md
    current-results.md
```

The implementation language is Rust for userspace. The production collector
path should be Rust userspace plus a small C/libbpf or Aya eBPF layer. The
eBPF side should parse, filter, and emit compact metadata; userspace should do
the sketching, planning, windowing, enrichment, and export.

## Architecture

FlowSketch separates the control plane from the data plane.

```text
Control plane
  query files / CLI / future Kubernetes CRD
    -> parser
    -> logical IR
    -> physical sketch planner
    -> resource and error checks

Data plane
  packet or flow source
    -> normalizer
    -> optional metadata enrichment
    -> sketch runtime
    -> window manager
    -> local estimates or snapshots
    -> Prometheus / OTLP / gateway
```

Supported and planned sources:

| Source | Status | Notes |
| ------ | ------ | ----- |
| pcap replay | Implemented | Deterministic testing and offline analysis |
| synthetic pcap | Implemented | Repeatable benchmark and correctness traces |
| Linux AF_PACKET | Implemented | Simple live Linux capture path |
| eBPF tc/XDP | Planned | First serious production collector |
| Cilium/Hubble receiver | Planned | Avoid duplicate capture in Cilium clusters |
| NetFlow/IPFIX/sFlow | Planned | Enterprise and ISP flow-log environments |
| AF_XDP | Later | Higher performance, higher operational burden |
| DPDK | Later | Specialized packet-processing deployments |
| P4/SmartNIC/DPU | Later | Research or vendor-partner tier |

The core design rule is simple: keep privileged packet collection small and
auditable. Put the query planner and sketch runtime in userspace.

## Packet Lifecycle

For a scanner query, the runtime flow looks like this:

```text
packet arrives
    -> collector extracts timestamp, 5-tuple, protocol, flags, byte count
    -> normalizer produces a FlowEvent
    -> optional enricher attaches node, interface, pod, namespace, service
    -> planner maps distinct_count(dst.ip) by src.ip to a bounded sketch plan
    -> runtime updates the active window bucket
    -> flush emits sources above the threshold
    -> exporter sends Prometheus or OTLP metrics
```

The wedge is useful because security and SRE teams get signals like
"sources scanning too many destinations" without storing every flow record.

## Data Model

The runtime normalizes traffic into `FlowEvent`:

```rust
pub struct FlowEvent {
    pub ts_nanos: u64,
    pub src_ip: IpAddr128,
    pub dst_ip: IpAddr128,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub bytes: u32,
    pub packets: u32,
    pub direction: Direction,
    pub tcp_flags: u8,
    pub interface_index: u32,
    pub node_id: u64,
    pub namespace_id: Option<u64>,
    pub pod_id: Option<u64>,
    pub service_id: Option<u64>,
}
```

Payload capture is deliberately out of scope by default.

Logical dimensions include:

```text
src.ip
dst.ip
src.port
dst.port
protocol
tcp.flags
direction
node.name
interface.name
k8s.cluster.name
k8s.namespace.name
k8s.pod.name
k8s.pod.uid
k8s.service.name
k8s.workload.name
```

Where Kubernetes metadata is available, FlowSketch should reuse OpenTelemetry
semantic conventions such as `k8s.cluster.name`, `k8s.node.name`,
`k8s.namespace.name`, `k8s.pod.uid`, `k8s.pod.name`, and `k8s.pod.ip`.

Estimates carry approximation metadata:

```rust
pub struct SketchEstimate {
    pub query_name: String,
    pub window_start_nanos: u64,
    pub window_end_nanos: u64,
    pub group: Vec<(String, String)>,
    pub estimate: f64,
    pub lower_bound: Option<f64>,
    pub upper_bound: Option<f64>,
    pub confidence: Option<f64>,
    pub algorithm: String,
    pub sketch_bytes: u64,
    pub update_count: u64,
}
```

The algorithm, memory, and error fields are part of the product. Approximation
must be visible to operators.

## Query Language

The current query language is YAML. YAML is easier than SQL to validate,
version, ship in ConfigMaps, and eventually wrap in Kubernetes CRDs.

Example current query:

```yaml
name: top_talkers
window:
  size: 60s
  slide: 10s
groupBy:
  - src.ip
  - dst.ip
measure:
  type: heavy_hitters
  value: bytes
  limit: 100
  error:
    epsilon: 0.001
export:
  prometheus: true
  maxSeries: 100
resources:
  maxMemory: 64MiB
```

Supported and planned primitives:

| Primitive | Example | Algorithm family |
| --------- | ------- | ---------------- |
| `count()` | packets per source | Count-Min or exact counters for low cardinality |
| `sum(bytes)` | bytes per source/destination | Count-Min or CountSketch |
| `heavy_hitters(bytes)` | top talkers | SpaceSaving, Misra-Gries, Count-Min plus candidates |
| `distinct_count(dst.ip)` | fan-out per source | HyperLogLog, HLLMap |
| `entropy(src.ip)` | DDoS distribution shift | SpaceSaving-head plus HLL-tail, UnivMon-like future |
| `quantile(value)` | packet-size p99 | KLL |
| `change(metric)` | adjacent-window change | paired sketches |
| `traffic_matrix(src,dst)` | service matrix | Count-Min, CountSketch, heavy-hitter matrix |

Longer term, FlowSketch can add a SQL-like layer:

```sql
SELECT src.ip, APPROX_COUNT_DISTINCT(dst.ip) AS fanout
FROM packets
WHERE protocol = 'tcp'
WINDOW 60s SLIDE 10s
GROUP BY src.ip
HAVING fanout > 5000;
```

That should come after the runtime and planner are proven. Starting with SQL
would create parsing and semantics debates too early.

## Planner And IR

The planner is the main differentiator. Users should not need to know which
sketch to choose.

Logical measures include:

```rust
pub enum Measure {
    Count,
    Sum(Field),
    HeavyHitters { value: Field, limit: usize },
    DistinctCount { field: Field },
    Entropy { field: Field },
    Change { measure: Box<Measure>, baseline: WindowSpec },
    Quantile { field: Field, q: f64 },
}
```

Physical sketch choices include:

```rust
pub enum PhysicalSketch {
    CountMin { width: usize, depth: usize, conservative_update: bool },
    CountSketch { width: usize, depth: usize },
    SpaceSaving { capacity: usize },
    MisraGries { capacity: usize },
    HyperLogLog { precision: u8 },
    HllMap { max_keys: usize, precision: u8 },
    Kll { k: usize },
    Composite { stages: Vec<PhysicalSketch> },
}
```

Planner decisions:

| Query | Preferred plan | Why |
| ----- | -------------- | --- |
| `sum(bytes) by src.ip` | Count-Min | nonnegative point estimates |
| `topk(src.ip, bytes)` | SpaceSaving or Misra-Gries | need candidate identities |
| `distinct_count(dst.ip) by src.ip` | HLLMap or heavy-source plus HLL | avoids unbounded HLL per source |
| `entropy(src.ip)` | distribution sketch | entropy needs more than point counts |
| `change(topk)` | paired sketches | compare current and baseline windows |
| `traffic_matrix(src.service,dst.service)` | exact if small, sketch if large | service labels may be manageable |

Every explain plan should show:

```text
algorithm
memory budget
window size and bucket count
estimated value semantics
error model and confidence
known failure modes
export series cap
```

## Algorithms

| Algorithm | Use in FlowSketch | Notes |
| --------- | ----------------- | ----- |
| Count-Min Sketch | approximate packet and byte counts, traffic matrices | mergeable, compact, biased high for nonnegative updates |
| CountSketch | signed updates, L2-heavy hitters, variance reduction | useful for turnstile-style extensions |
| HyperLogLog | distinct source or destination counts | compact, standard, mergeable cardinality estimator |
| HLLMap | grouped distinct counts | bounded keyed cardinality for fan-out queries |
| SpaceSaving | top-k talkers and elephant flows | practical bounded candidate tracking |
| Misra-Gries | deterministic heavy-hitter candidates | simple and useful as a baseline |
| KLL | packet-size and flow-size quantiles | distribution summaries, not just counts |
| ExactCounter | tests and ground truth | not for unbounded production queries |

The project should learn from:

| System or body of work | What to take from it |
| ---------------------- | -------------------- |
| Apache DataSketches | production-grade algorithm engineering and mergeability |
| Sonata | high-level query intent over streaming traffic |
| PSketch | commodity Linux eBPF sketch monitoring direction |
| Sketchy With a Chance of Adoption | adoption blockers: intent translation, resource allocation, composition, heterogeneous targets |
| Cilium/Hubble | Kubernetes-native network visibility and service-map integration |
| OpenTelemetry | normal telemetry pipeline integration instead of a proprietary backend |

## Runtime Design

High-throughput telemetry should avoid global locks.

```text
per-core collector
    -> per-core sketch shard
    -> periodic local flush
    -> node-local merge
    -> export or gateway push
```

The core sketch trait shape is:

```rust
pub trait Sketch {
    fn update(&mut self, key: &[u8], value: u64);
    fn estimate(&self, key: &[u8]) -> f64;
    fn merge(&mut self, other: &Self) -> Result<(), SketchError>;
    fn memory_bytes(&self) -> usize;
    fn reset(&mut self);
}
```

Windowing model:

| Window | Use |
| ------ | --- |
| Tumbling | simple periodic summaries |
| Sliding | detection over rolling intervals |
| Exponential decay | future long-running trend summaries |

The MVP model is a sliding window implemented as a ring of tumbling buckets.
For example, a 60 second window with a 10 second slide is six buckets.

Hashing is treated as part of compatibility:

```rust
pub struct HashSpec {
    pub family: HashFamily,
    pub seed: u64,
    pub version: u16,
}
```

FlowSketch needs fixed seeded hash families, per-query seed isolation, stable
cross-node seeds for mergeability, optional secret seeds for adversarial
environments, and hash-version metadata in exported estimates.

## Distributed Aggregation

Node-local agents are useful, but cluster-wide questions need merging:

```text
agent on node A --\
agent on node B ----> flowsketch-gateway -> Prometheus / OTLP / Kafka
agent on node C --/
```

Implemented today:

- agents can push FSK1 snapshot batches to the gateway
- the gateway validates algorithm, hash seed, sketch parameters, and windows
- compatible snapshots are merged
- cluster-level `/metrics` and `/v1/nodes` are served by the gateway

Sketches can only merge if these match:

```text
algorithm
version
hash family
seed
width / depth / precision / capacity
window boundaries
key encoding
snapshot format
```

Incompatible merges must be rejected and exposed as health metrics.

## Export APIs

Prometheus:

```text
GET /metrics
GET /healthz
GET /readyz
GET /v1/queries
GET /v1/nodes          # gateway
```

Example metric shape:

```text
flowsketch_query_estimate{
  query="suspected_scanners",
  algorithm="hllmap",
  error_kind="relative",
  window="60s"
} 7132
```

OTLP:

```yaml
export:
  otlp:
    endpoint: http://otel-collector.observability.svc:4318/v1/metrics
```

OpenTelemetry resource attributes should include `service.name`,
`host.name`, `k8s.cluster.name`, `k8s.node.name`, `k8s.namespace.name`,
`k8s.pod.name`, `cloud.provider`, and `cloud.region` where available.

Metric attributes should include:

```text
flowsketch.query.name
flowsketch.algorithm
flowsketch.window
flowsketch.error.kind
flowsketch.error.epsilon
flowsketch.error.delta
network.protocol.name
source.address
destination.address
source.port
destination.port
```

Raw IP labels must be capped, hashed, prefix-aggregated, or omitted where
cardinality would harm the backend.

Future native APIs:

```text
ApplyQuery
DeleteQuery
ListQueries
ExplainQuery
StreamEstimates
PushSketch
StreamSketches
```

gRPC should be used for control-plane sync and high-volume structured
snapshot transport once the HTTP prototype is outgrown.

## Kubernetes

The intended deployment model is:

```text
one FlowSketch agent per node
    -> node-local packet observation
    -> node-local sketches
    -> gateway merges compatible snapshots
    -> OTel / Prometheus export
```

Current deployment assets:

- `deploy/kubernetes/namespace.yaml`
- `deploy/kubernetes/rbac.yaml`
- `deploy/kubernetes/config.yaml`
- `deploy/kubernetes/gateway.yaml`
- `deploy/kubernetes/agent-daemonset.yaml`
- `deploy/kubernetes/pdb.yaml`
- `deploy/kubernetes/networkpolicy.yaml` as an optional template
- `deploy/kubernetes/kustomization.yaml`

Deploy the baseline manifests:

```bash
kubectl apply -k deploy/kubernetes
```

The optional NetworkPolicy must be reviewed before use. The agent uses
`hostNetwork: true`, and some CNIs classify that traffic by node IP rather
than pod labels.

Future Kubernetes surface:

```text
flowsketch-agent DaemonSet
flowsketch-gateway Deployment
flowsketch-operator Deployment
SketchQuery CRD
Helm chart
Grafana dashboards
PrometheusRule templates
ServiceMonitor / PodMonitor templates
```

Future CRD shape:

```yaml
apiVersion: flowsketch.io/v1alpha1
kind: SketchQuery
metadata:
  name: namespace-fanout
spec:
  selector:
    namespaces:
      - payments
      - checkout
  window:
    size: 60s
    slide: 10s
  groupBy:
    - k8s.namespace.name
    - k8s.service.name
  measure:
    type: distinct_count
    field: dst.ip
  resources:
    maxMemory: 32MiB
    maxSeries: 500
  export:
    otlp: true
    prometheus: true
```

The operator should validate queries, explain physical plans in status, roll
out configs to agents, enforce team or namespace budgets, manage gateways, and
surface health.

## Security And Privacy

Default posture:

```text
no payload capture
no DNS content capture unless explicitly enabled
no full packet storage
bounded debug sampling
IP hashing available
prefix aggregation available
label allowlist required
query memory and series caps
```

Runtime safety signals should include:

```text
flowsketch_agent_dropped_events_total
flowsketch_agent_kernel_dropped_packets_total
flowsketch_agent_runtime_batches_total
flowsketch_agent_runtime_shards
flowsketch_agent_ring_buffer_utilization
flowsketch_agent_cpu_seconds_total
flowsketch_agent_memory_bytes
flowsketch_agent_sketch_memory_bytes
flowsketch_agent_export_failures_total
flowsketch_agent_queries_active
flowsketch_agent_queries_rejected_total
```

Kubernetes permissions should be minimal: read pods, namespaces, services,
endpoints, nodes, and future `SketchQuery` CRDs. The agent should not need
secret reads except through explicitly mounted exporter credentials.

See [`docs/security.md`](docs/security.md) for the current security notes.

## Example Queries

Top talkers:

```yaml
name: top_talkers
window:
  size: 60s
  slide: 10s
groupBy:
  - src.ip
  - dst.ip
measure:
  type: heavy_hitters
  value: bytes
  limit: 100
```

Suspected scanners:

```yaml
name: suspected_scanners
window:
  size: 60s
  slide: 10s
match:
  protocol: tcp
  dst.port: [22, 80, 443, 5432, 6379]
groupBy:
  - src.ip
measure:
  type: distinct_count
  field: dst.ip
alertIf:
  gt: 5000
```

Protocol bytes:

```yaml
name: protocol_bytes
window:
  size: 60s
  slide: 10s
groupBy:
  - protocol
measure:
  type: sum
  field: bytes
```

Packet-size quantiles:

```yaml
name: flow_size_quantiles
window:
  size: 60s
  slide: 10s
measure:
  type: quantile
  field: bytes
  q: 0.99
```

Source entropy:

```yaml
name: source_entropy
window:
  size: 60s
  slide: 10s
measure:
  type: entropy
  field: src.ip
```

Future examples include namespace fan-out, service traffic matrices, DDoS
entropy shifts, and adjacent-window change detection once Kubernetes metadata
and change queries land.

## Integrations

### OpenTelemetry

FlowSketch should primarily act as an OTLP producer:

```text
FlowSketch agent
    -> OTLP metrics
    -> OpenTelemetry Collector / Grafana Alloy / Datadog Collector
    -> backend
```

Later, FlowSketch can become an OpenTelemetry Collector receiver:

```yaml
receivers:
  flowsketch:
    queries:
      - /etc/flowsketch/queries/*.yaml
    source:
      ebpf:
        interfaces: ["eth0"]

service:
  pipelines:
    metrics:
      receivers: [flowsketch]
      exporters: [otlp, prometheusremotewrite]
```

### Grafana

Grafana adoption should go through Prometheus and OTLP first.

Grafana would want:

- Alloy examples
- official dashboards
- Prometheus recording rules
- Mimir-compatible metrics
- Loki anomaly-event export later
- Helm chart and Kubernetes dashboards

Dashboards to ship:

| Dashboard | Panels |
| --------- | ------ |
| Network Heavy Hitters | top source/destination pairs, bytes, packets, rank, error |
| Scanner Detection | distinct destinations by source, threshold events |
| Service Fan-Out | namespace and service fan-out over time |
| DDoS Signals | entropy, source cardinality, heavy hitters |
| Agent Health | CPU, drops, queue pressure, sketch memory |
| Accuracy and Resource | memory, width/depth, export series count |

### Datadog

Datadog adoption should start with OTLP metrics or OpenMetrics scrape.

Datadog would want:

- stable metric names
- bounded tag cardinality
- dashboard JSON
- monitor templates
- OpenMetrics integration option
- Cloud SIEM rule examples
- Kubernetes and service ownership tags

Metric names should look like:

```text
flowsketch.network.bytes.estimated
flowsketch.network.distinct_destinations.estimated
flowsketch.network.heavy_hitter.rank
flowsketch.network.entropy.estimated
flowsketch.agent.dropped_events
flowsketch.agent.sketch_memory_bytes
```

Suggested tags:

```text
env
service
team
cluster_name
kube_namespace
kube_service
query_name
algorithm
window
```

Raw IP tags need strict caps or hashing.

### Cilium And Hubble

FlowSketch should complement Cilium/Hubble, not compete with it.

A Hubble receiver would let Cilium clusters reuse existing flow visibility and
add approximate high-cardinality summaries on top:

```text
Cilium/Hubble flow visibility
    -> FlowSketch Hubble receiver
    -> approximate high-cardinality summaries
```

### Cloud Providers

The cloud-provider shape is one of:

```text
node/host agent
VPC flow-log pre-aggregation
managed Kubernetes telemetry add-on
```

The value is cheaper high-cardinality telemetry, privacy-preserving summaries,
tenant-safe aggregation, and DDoS/security signals without exporting all raw
flow records.

## Benchmarks

Correctness datasets:

```text
synthetic uniform
synthetic Zipf
synthetic scanner
synthetic DDoS
CAIDA traces where legally available
MAWI traces where legally available
small pcap fixtures
```

Correctness metrics:

| Metric | Meaning |
| ------ | ------- |
| ARE | average relative error |
| AAE | average absolute error |
| precision@k | top-k correctness |
| recall@k | missed heavy hitters |
| false positives | incorrect scanner or DDoS signals |
| false negatives | missed anomalies |
| update throughput | events/sec/core |
| memory/query | bytes |
| export cardinality | emitted time series |
| dropped events | collector pressure |

Systems targets:

```text
1 Gb/s: easy MVP
10 Gb/s: credible v1
25/40 Gb/s: serious infrastructure
100 Gb/s: future high-performance collector tier
```

Test modes:

| Mode | Target |
| ---- | ------ |
| pcap replay | correctness and repeatability |
| AF_PACKET | simple live baseline |
| eBPF tc | production Linux path |
| XDP | higher-performance Linux path |
| Hubble receiver | Kubernetes/Cilium path |
| AF_XDP or DPDK | specialized 100G+ deployments |

The current harness reports:

- parsed events and packets read
- average L3 packet size
- observed timestamp rate from the trace
- measured parser/runtime throughput
- direct projected L3 Gb/s per core
- target events/sec for 1/10/25/40/100 Gb/s
- estimated cores needed for the selected target
- runtime memory, estimate count, and late events

See [`benchmarks/README.md`](benchmarks/README.md).

## Milestones

These are the project milestones that matter now. Each one should be backed by
commands, datasets, and acceptance criteria rather than vague performance
claims.

| Milestone | Target | Status | Acceptance criteria |
| --------- | ------ | ------ | ------------------- |
| M0: credible v0 | useful offline approximate telemetry | substantially done | pcap replay, synthetic traces, YAML queries, explain output, Prometheus output, exact-vs-approx tests |
| M1: local agent | live userspace telemetry on Linux | baseline done | AF_PACKET source, HTTP health/readiness, `/metrics`, bounded memory, safe startup/shutdown |
| M2: distributed v0 | node-local agents plus cluster merge | baseline done | snapshot push, compatibility validation, gateway `/metrics`, node inventory |
| M3: 10 Gb/s projected path | 10 Gb/s mixed-packet projection within a CPU budget | local baseline done | `flowsketch bench --trace ... --profile 10g --core-budget 2` passes on representative traces |
| M4: 10 Gb/s live Linux | real 10 Gb/s capture without silent loss | partial | AF_PACKET socket and userspace drop counters exist; dedicated-NIC replay, CPU profile, and exact replay comparison remain |
| M5: Kubernetes v1 | normal platform-team deployment | partial | raw deployment, ServiceMonitor/PodMonitor, PrometheusRule, and resource defaults exist; Helm and metadata enrichment remain |
| M6: eBPF collector | production Linux ingest path | prepared | tc ingress program, ring-buffer drop counters, verifier-safe parser, userspace fallback |
| M7: 25/40 Gb/s | serious infrastructure traffic | runtime partial | merge-correct sharded runtime and balanced dispatch exist; direct RSS queue mapping, CPU pinning, live replay, and p99 latency remain |
| M8: 100 Gb/s mixed traffic | realistic 100G packet-size distribution | not done | XDP/eBPF or AF_XDP path, sharded userspace, live NIC validation, public benchmark report |
| M9: 100 Gb/s minimum packets | 148.8Mpps worst case | research/hardware tier | XDP prefiltering, AF_XDP/DPDK or hardware offload, sampling/preaggregation strategy |
| M10: production v1 | trusted operational deployment | not done | security posture, auth/TLS guidance, HA gateway story, dashboards, alerts, runbooks, upgrade tests |

The immediate milestone is M4, then the capture side of M7. M4 is the first
milestone that can honestly claim "10 Gb/s" in a live environment.

## Roadmap

### Phase 0: Scope Lock

Define the charter, supported query primitives, supported algorithms, export
paths, and non-goals.

First-six-month non-goals:

```text
No P4
No DPDK
No SmartNIC
No inline packet modification
No packet payload capture
No custom database
No full SIEM
No full SQL parser
```

### Phase 1: Core Algorithms

Implemented substantially today.

Scope:

```text
flowsketch-core
flowsketch-algos
Count-Min
CountSketch
HyperLogLog
HLLMap
SpaceSaving
Misra-Gries
KLL
exact baseline
```

Acceptance criteria:

```text
>5M updates/sec/core in userspace synthetic benchmark
stable serialization format
merge compatibility checks
documented error model for each algorithm
```

### Phase 2: Offline Replay

Implemented substantially today.

Scope:

```text
flowsketch-pcap
flowsketch-cli
basic query YAML
Prometheus text output
synthesized pcap traces
```

Acceptance criteria:

```text
reads pcap
extracts IPv4/IPv6/TCP/UDP
runs useful queries
exports Prometheus text
has reproducible benchmark suite
```

### Phase 3: Userspace Live Agent

Implemented as a baseline.

Scope:

```text
flowsketch-agent
pcap source
Linux AF_PACKET source
HTTP /metrics
HTTP /healthz and /readyz
/v1/queries
bounded HTTP handling
merge-correct runtime shards and bounded event batches
AF_PACKET socket-drop and userspace backpressure counters
```

Still needed:

```text
config reload
better lifecycle controls
more live Linux soak tests
PACKET_MMAP/eBPF/XDP capture paths
```

### Phase 4: OTLP Export

Implemented as OTLP/HTTP+JSON metrics export.

Still needed:

```text
more semantic convention coverage
larger collector compatibility matrix
anomaly event/log export
TLS/auth story through sidecar, mesh, or collector
```

### Phase 5: Kubernetes-Native MVP

Partially implemented through raw manifests.

Implemented:

```text
Namespace
RBAC
ConfigMaps
agent DaemonSet
gateway Deployment and Service
PodDisruptionBudget
optional NetworkPolicy template
```

Still needed:

```text
Helm chart
ServiceMonitor / PodMonitor
SketchQuery CRD
operator
Kubernetes metadata enrichment
Grafana dashboards
PrometheusRule templates
```

### Phase 6: eBPF Collector

Prepared but not implemented.

Current status:

```text
flowsketch-ebpf contract crate exists
docs/ebpf-roadmap.md exists
userspace FlowEvent conversion is tested
```

Target design:

```text
eBPF:
  parse L2/L3/L4
  apply cheap filters
  emit compact FlowEvent

userspace:
  enrich
  sketch
  window
  export
```

Acceptance criteria:

```text
loads on supported kernels
fails closed if verifier rejects the program
does not alter packets
overhead benchmarked
supports tc ingress
supports IPv4/IPv6/TCP/UDP
exposes ring-buffer drop counters
```

### Phase 7: Cluster Gateway

Implemented as an HTTP snapshot gateway.

Still needed:

```text
gateway HA and sharding
larger merge benchmarks
gRPC transport
backpressure and admission controls
persistent or replicated state story
```

### Phase 8: Query Planner v1

Partially implemented.

Implemented:

```text
logical IR
physical IR
memory estimation
error contracts
query explain
query rejection for unsafe shapes
```

Still needed:

```text
more query primitives
more adaptive plan choices
cost model tied to benchmark data
Kubernetes-aware planning
```

### Phase 9: Advanced Integrations

Future:

| Integration | Why |
| ----------- | --- |
| Cilium/Hubble receiver | avoid duplicate packet capture in Cilium clusters |
| OpenTelemetry Collector receiver | embed into collector distributions |
| Grafana Alloy component | first-class Grafana path |
| Datadog Agent/OpenMetrics integration | first-class Datadog path |
| ClickHouse sink | large event analytics |
| Kafka sink | security and event pipelines |
| Terraform/Helm modules | enterprise adoption |
| PrometheusRule templates | alerting out of the box |

### Phase 10: Advanced Backends

Later:

| Backend | Why later |
| ------- | --------- |
| AF_XDP | more performance, more operational complexity |
| DPDK | invasive for normal users |
| P4 | good research story, not an MVP |
| SmartNIC/DPU | requires vendor-specific work |
| WASM plugins | useful, but adds security and reliability risk |

## Production Readiness

FlowSketch is close to a serious v0, not close to a fully production-hardened
100 Gb/s system.

What is solid:

- tested sketch algorithms
- deterministic pcap replay
- query parsing and explain output
- Prometheus and OTLP export paths
- bounded HTTP handling in agent/gateway paths
- snapshot format and merge compatibility checks
- cross-platform developer CI
- Docker/systemd/Kubernetes starting points

What is missing before a production v1:

- live Linux capture validation under real traffic
- eBPF/XDP loss accounting (AF_PACKET kernel and userspace drops are counted)
- eBPF tc/XDP collector
- direct parallel RX-queue ingestion and CPU affinity (runtime execution is sharded)
- gateway HA/sharding or clear single-writer semantics
- TLS/auth/deployment guidance for non-local HTTP endpoints
- Kubernetes metadata, Helm, CRD, and operator
- real trace benchmark suite using legally available traces
- live 10/25/40/100 Gb/s validation on actual NICs
- dashboards, alerts, and runbooks

See [`docs/production-readiness.md`](docs/production-readiness.md).

## Highest-Value Improvements

If the next work is about making FlowSketch more real, prioritize this order:

1. Build the eBPF tc/XDP ingress collector and expose ring-buffer drop counters.
2. Feed runtime shards directly from RSS/RX queues and add CPU affinity, avoiding the serial parser/dispatcher.
3. Benchmark AF_PACKET, eBPF tc, and XDP on Linux with real CAIDA/MAWI-style traces and hardware replay where available.
4. Add Kubernetes metadata enrichment for node, namespace, pod, service, and workload dimensions.
5. Turn the manifests and existing Prometheus Operator monitoring pack into a Helm chart.
6. Add gateway HA strategy: sharding, leader election, replicated state, or explicit single-gateway semantics.
7. Add auth/TLS guidance through mesh, reverse proxy, or collector-side deployment patterns.
8. Publish Grafana dashboards and Datadog/OpenMetrics examples.
9. Add a conformance suite for sketch snapshots and query-planner behavior.
10. Keep tightening benchmark documentation so claims are tied to commands and datasets.

## Engineering Effort

Rough estimates for a strong small team:

| Milestone | Estimate |
| --------- | -------- |
| Core sketches and replay CLI | 1-2 months |
| Live userspace agent and Prometheus | 2-3 months |
| OTLP export and basic dashboards | 1 month |
| Kubernetes DaemonSet and metadata | 2-3 months |
| eBPF collector | 3-6 months |
| Distributed gateway | 2-4 months |
| Planner v1 | 3-6 months |

A credible public MVP is realistic in 4-6 months for a strong small team.
A production-trustworthy v1 is more like 12-18 months.
Apache-scale maturity is a multi-year project.

Difficulty by subsystem:

| Subsystem | Difficulty |
| --------- | ---------- |
| Basic sketch algorithms | 4/10 |
| Correct merge and window semantics | 7/10 |
| Query planner | 8/10 |
| Prometheus export | 3/10 |
| OTLP export | 5/10 |
| Kubernetes metadata | 6/10 |
| eBPF collector | 8/10 |
| High-throughput reliability | 8/10 |
| Distributed merge | 7/10 |
| Enterprise trust and security | 9/10 |

## Risks

| Risk | Mitigation |
| ---- | ---------- |
| It becomes just another sketch crate | Lead with agent, planner, and standard exports |
| Prometheus cardinality explosion | Hard caps, top-k defaults, hashed or prefix IP labels, query rejection |
| eBPF complexity dominates the project | Keep pcap and AF_PACKET useful; keep kernel logic minimal |
| Existing vendors absorb the idea | Stay neutral, portable, and backend-agnostic |
| Approximate results are not trusted | Expose error contracts, exact-vs-approx benchmarks, and explain plans |
| 100 Gb/s claims outrun reality | Tie every performance claim to benchmark commands and hardware context |

## Why This Could Matter

FlowSketch sits downstream of the streaming and sketching research lineage:

```text
streaming algorithms
    -> Count-Min, CountSketch, HLL, heavy hitters, quantiles
    -> network telemetry sketches
    -> production runtime, planner, collector, and exporters
```

The hard part is not only the math. The hard part is systems engineering:

```text
packet collection
windowing
merge semantics
query planning
resource control
export cardinality
Kubernetes metadata
eBPF safety
observability integration
operator trust
```

That is the gap FlowSketch is trying to fill: the production systems layer
that makes sketching useful to SRE, network, security, and observability teams.

## Build Order

The practical order remains:

```text
1. flowsketch-core
2. flowsketch-algos
3. flowsketch-pcap
4. flowsketch-cli
5. flowsketch-prometheus
6. flowsketch-agent
7. flowsketch-otel
8. flowsketch-gateway
9. Kubernetes metadata and Helm
10. eBPF tc/XDP collector
11. planner v1 expansion
12. Hubble, Datadog, Grafana, ClickHouse, Kafka
13. AF_XDP, DPDK, P4, SmartNIC
```

The project has already moved through the early runtime and agent pieces. The
next major threshold is credible Linux production ingestion.

## Documentation

- [`docs/operator-guide.md`](docs/operator-guide.md)
- [`docs/query-language.md`](docs/query-language.md)
- [`docs/accuracy-contracts.md`](docs/accuracy-contracts.md)
- [`docs/algorithm-notes.md`](docs/algorithm-notes.md)
- [`docs/security.md`](docs/security.md)
- [`docs/production-readiness.md`](docs/production-readiness.md)
- [`docs/ebpf-roadmap.md`](docs/ebpf-roadmap.md)
- [`benchmarks/README.md`](benchmarks/README.md)
- [`deploy/kubernetes/README.md`](deploy/kubernetes/README.md)

## Final Position

The weak version of this project is "we implemented sketches."

The strong version is:

> FlowSketch is the runtime that compiles network observability intent into
> bounded-memory sketch execution, then exports the results through normal
> Prometheus and OpenTelemetry pipelines.

That is coherent, technically defensible, and useful. It is also still early.
The core is promising; production credibility now depends on parallel Linux
ingest, eBPF/XDP loss accounting, Kubernetes integration, and public hardware
benchmarks that make the performance claims reproducible.
