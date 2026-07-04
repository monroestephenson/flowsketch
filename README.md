# FlowSketch: complete implementation plan

> ## Implementation status
>
> The **minimum credible v0** (§26, build order §30) is implemented as a Rust
> workspace: `flowsketch-core`, `flowsketch-algos` (Count-Min, CountSketch,
> HyperLogLog, HLLMap, SpaceSaving, Misra-Gries + exact baseline),
> `flowsketch-ir`, `flowsketch-planner`, `flowsketch-runtime`,
> `flowsketch-pcap`, `flowsketch-prometheus`, `flowsketch-gateway`, and
> `flowsketch-cli`.
>
> ```bash
> cargo build --release
> target/release/flowsketch synth --out demo.pcap --packets 200000
> target/release/flowsketch explain examples/queries/suspected-scanners.yaml
> target/release/flowsketch replay demo.pcap \
>   --query examples/queries/top-talkers.yaml \
>   --query examples/queries/suspected-scanners.yaml
> ```
>
> Beyond the v0 MVP, the following are also implemented:
>
> - **live agent** (`flowsketch-agent`, Phase 3): pcap replay on every
>   supported developer platform, plus Linux AF_PACKET live capture, feeding
>   the engine with HTTP `/metrics`, `/healthz`, `/readyz`, and `/v1/queries`
>   (`flowsketch agent --config examples/agent.yaml`)
> - **KLL quantile sketch** and the `quantile` measure (e.g. packet-size p99)
> - **entropy measure** (ungrouped): SpaceSaving-head + HLL-tail estimator
> - **cross-process sketch merge**: `flowsketch replay --snapshot-out` +
>   `flowsketch merge-snapshots` (the Phase 7 distributed-merge primitive)
> - **OTLP metrics export** (Phase 4): the agent pushes estimates to any
>   OpenTelemetry Collector / Grafana Alloy / Datadog OTel endpoint over
>   OTLP/HTTP+JSON with OTel semantic conventions, batching, and retry
> - **cluster gateway** (`flowsketch-gateway`, Phase 7): agents push their
>   window's FSK1 sketch snapshots (`export.gateway` in the agent config);
>   the gateway validates merge compatibility, combines them across nodes,
>   and serves cluster-level estimates on `/metrics` plus node inventory on
>   `/v1/nodes` (`flowsketch gateway --config examples/gateway.yaml`)
>
> See `docs/operator-guide.md`, `docs/query-language.md`,
> `docs/accuracy-contracts.md`, `docs/algorithm-notes.md`, and
> `docs/security.md`, `docs/production-readiness.md`,
> `docs/ebpf-roadmap.md`, and `benchmarks/README.md`. Everything below
> this block is the original design plan; Kubernetes manifests and the
> eBPF event-contract crate exist, but the eBPF collector itself is not
> yet built.

## 0. Core thesis

Build **FlowSketch** as a **portable sketch-based network telemetry runtime**, not as a generic sketch library.

The existing OSS gap is not “nobody has implemented Count-Min Sketch or HyperLogLog.” Apache DataSketches already provides production-quality sketch libraries across Java, C++, Python, Rust, and Go, including count-distinct, quantiles, frequent-items, and system integrations.

The greenfield opportunity is this:

> **A production network telemetry system that lets operators declare high-cardinality network questions, compiles those questions into bounded-memory sketches, runs them close to traffic, and exports normal OpenTelemetry/Prometheus signals.**

This is directly aligned with recent research. Sketch-based telemetry is considered attractive because sketches offer resource efficiency and accuracy guarantees, but adoption is blocked by unresolved systems problems: translating operator intent into sketches, managing resources, composing sketch types, and deploying across heterogeneous network platforms.

---

# 1. What the system should be

## One-sentence product

**FlowSketch is an approximate network telemetry agent and runtime for answering real-time high-cardinality questions such as top talkers, distinct destinations, fan-out, entropy shifts, scanning behavior, and traffic-matrix changes with fixed memory and explicit error bounds.**

## What it is not

It should **not** be:

| Bad framing            | Why it fails                                                                                    |
| ---------------------- | ----------------------------------------------------------------------------------------------- |
| “A sketch library”     | Apache DataSketches already covers much of that library category.                               |
| “A packet sniffer”     | tcpdump/Wireshark/pcap already exist.                                                           |
| “A Cilium competitor”  | Cilium/Hubble already provides exact/near-exact Kubernetes network visibility and service maps. |
| “A new SIEM”           | Datadog, Splunk, Elastic, CrowdStrike, etc. already own that workflow.                          |
| “A new network stack”  | Too much adoption drag.                                                                         |
| “A new query database” | Wrong layer.                                                                                    |

## Correct framing

```text
Existing traffic / packets / flow logs
        ↓
FlowSketch collector
        ↓
Sketch runtime + query planner
        ↓
Approximate telemetry results
        ↓
OpenTelemetry / Prometheus / Kafka / ClickHouse / Datadog / Grafana
```

It should feel operationally similar to:

* OpenTelemetry Collector
* Prometheus node exporter
* Cilium/Hubble
* Grafana Alloy
* Datadog Agent

But algorithmically, it should be based on streaming/sketching techniques.

---

# 2. Reference architecture

## High-level architecture

```text
┌────────────────────────────────────────────────────────────┐
│                       Control Plane                         │
│                                                            │
│  Config API / CLI / Kubernetes CRD / Policy Validator       │
│                         ↓                                  │
│  Query Parser → Logical IR → Physical Sketch Planner        │
│                         ↓                                  │
│  Resource Budgeter / Error Estimator / Deployment Planner   │
└────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────┐
│                        Data Plane                           │
│                                                            │
│  Packet / Flow Sources                                     │
│  - pcap / AF_PACKET                                        │
│  - eBPF tc/XDP                                             │
│  - AF_XDP later                                            │
│  - Cilium/Hubble receiver                                  │
│  - NetFlow/IPFIX/sFlow later                               │
│                         ↓                                  │
│  Normalizer → Metadata Enricher → Sketch Runtime            │
│                         ↓                                  │
│  Window Manager → Local Aggregator → Merge Engine           │
│                         ↓                                  │
│  Exporters: Prometheus / OTLP / Kafka / ClickHouse / gRPC   │
└────────────────────────────────────────────────────────────┘
```

The key design choice: **keep the kernel/eBPF program small** and place most complexity in userspace. eBPF is powerful because it can safely run sandboxed programs in privileged kernel contexts and is widely used for networking, observability, and security, but the verifier, maps, helper calls, and kernel compatibility constraints make complex in-kernel logic risky.

---

# 3. End-to-end packet lifecycle

## Example: detecting scanners

Query:

```yaml
queries:
  - name: suspected_scanners
    every: 10s
    window: 60s
    group_by:
      - src.ip
    estimate:
      distinct_count: dst.ip
    where:
      protocol: tcp
      dst.port: [22, 80, 443, 5432, 6379]
    alert_if:
      gt: 5000
    export:
      metrics: true
      exemplars: true
```

Runtime lifecycle:

```text
Packet arrives
    ↓
Collector extracts 5-tuple:
(src_ip, dst_ip, src_port, dst_port, proto, bytes, timestamp)
    ↓
Normalizer maps packet → FlowEvent
    ↓
Metadata enricher attaches:
node, interface, k8s namespace, pod, service, workload
    ↓
Query planner maps query:
distinct_count(dst.ip) grouped by src.ip
    ↓
Physical plan:
HLL-per-heavy-source OR HLLMap-like sketch
    ↓
Runtime updates sketch
    ↓
Every 10s:
emit src_ip values whose estimated distinct dst_ip count > 5000
    ↓
Export as:
- OTLP metric
- Prometheus metric
- optional structured log/event
```

This is the right wedge because it gives security/SRE teams a useful signal without storing every flow record.

---

# 4. Module breakdown

## 4.1 Repository structure

A serious Apache-style project should be multi-crate/multi-module from the start.

```text
flowsketch/
  crates/
    flowsketch-core/          # sketch traits, hashers, common types
    flowsketch-algos/         # Count-Min, CountSketch, HLL, SpaceSaving, etc.
    flowsketch-ir/            # logical/physical query IR
    flowsketch-planner/       # sketch selection + memory/error planning
    flowsketch-runtime/       # windows, sharding, merge, scheduler
    flowsketch-agent/         # host agent daemon
    flowsketch-ebpf/          # eBPF C/Rust skeletons
    flowsketch-pcap/          # offline replay
    flowsketch-k8s/           # Kubernetes metadata, CRDs, Helm
    flowsketch-otel/          # OTLP exporter/receiver integration
    flowsketch-prometheus/    # /metrics exporter
    flowsketch-clickhouse/    # optional batch export
    flowsketch-kafka/         # optional event export
    flowsketch-api/           # gRPC/HTTP API
    flowsketch-cli/           # CLI
  proto/
    flowsketch/v1/*.proto
  deploy/
    helm/
    systemd/
    docker/
  benchmarks/
    caida/
    mawi/
    synthetic/
  docs/
    query-language.md
    accuracy-contracts.md
    operator-guide.md
    algorithm-notes.md
```

Recommended implementation language: **Rust userspace + C or Aya/libbpf eBPF layer**.

Reason: Rust is appropriate for a low-level agent with memory safety, concurrency, and C ABI support; eBPF programs still often require C-like restrictions because the kernel verifier is the real target.

---

# 5. Data model

## 5.1 Raw event

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

This deliberately excludes payload content. The privacy posture should be: **headers and metadata only by default**.

## 5.2 Logical dimensions

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

For Kubernetes, FlowSketch should reuse OpenTelemetry semantic conventions where possible. OTel’s Kubernetes resource conventions define attributes such as `k8s.cluster.name`, `k8s.node.name`, `k8s.namespace.name`, `k8s.pod.uid`, `k8s.pod.name`, `k8s.pod.ip`, and pod labels.

## 5.3 Aggregation output

```rust
pub struct SketchEstimate {
    pub query_name: String;
    pub window_start_nanos: u64;
    pub window_end_nanos: u64;

    pub group: Vec<(String, String)>;

    pub estimate: f64;
    pub lower_bound: Option<f64>;
    pub upper_bound: Option<f64>;
    pub confidence: Option<f64>;

    pub algorithm: String;
    pub sketch_bytes: u64;
    pub update_count: u64;
}
```

The `algorithm`, `sketch_bytes`, and error/confidence fields are important. They make the approximation visible instead of hiding it.

---

# 6. Query language

## 6.1 MVP YAML DSL

Start with YAML, not SQL. YAML is easier to validate, version, ship as Kubernetes CRDs, and translate into an internal IR.

```yaml
apiVersion: flowsketch.io/v1alpha1
kind: SketchQuery
metadata:
  name: top-talkers
spec:
  interval: 10s
  window:
    size: 60s
    slide: 10s

  match:
    protocol: tcp
    interfaces: ["eth0"]

  groupBy:
    - src.ip
    - dst.ip

  measure:
    type: heavy_hitters
    value: bytes
    limit: 100
    error:
      epsilon: 0.001
      delta: 0.01

  export:
    prometheus:
      enabled: true
    otlp:
      enabled: true
```

## 6.2 Query primitives

| Primitive                 | Example                             | Algorithm family                              |
| ------------------------- | ----------------------------------- | --------------------------------------------- |
| `count()`                 | packets per source                  | Count-Min, exact counters for low-cardinality |
| `sum(bytes)`              | bytes per 5-tuple                   | Count-Min / CountSketch                       |
| `heavy_hitters(bytes)`    | top talkers                         | SpaceSaving, Misra-Gries, Count-Min + heap    |
| `distinct_count(dst.ip)`  | fan-out per source                  | HyperLogLog / CPC / HLLMap-style              |
| `entropy(src.ip)`         | entropy shifts during DDoS          | UnivMon-style or sampled distribution sketch  |
| `change(metric)`          | sudden traffic change               | paired sketches over adjacent windows         |
| `quantile(value)`         | latency/inter-arrival distributions | KLL / t-digest                                |
| `traffic_matrix(src,dst)` | approximate service traffic matrix  | Count-Min / CountSketch / heavy-hitter matrix |

## 6.3 Longer-term SQL-like layer

Later:

```sql
SELECT src.ip, APPROX_COUNT_DISTINCT(dst.ip) AS fanout
FROM packets
WHERE protocol = 'tcp'
WINDOW 60s SLIDE 10s
GROUP BY src.ip
HAVING fanout > 5000;
```

Do **not** start here. SQL introduces parsing and semantics debates before the runtime is proven.

---

# 7. Internal IR

## 7.1 Logical IR

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

pub struct LogicalQuery {
    pub name: String,
    pub filter: Predicate,
    pub group_by: Vec<Field>,
    pub measure: Measure,
    pub window: WindowSpec,
    pub error: ErrorSpec,
    pub export: ExportSpec,
}
```

## 7.2 Physical IR

```rust
pub enum PhysicalSketch {
    CountMin {
        width: usize,
        depth: usize,
        conservative_update: bool,
    },
    CountSketch {
        width: usize,
        depth: usize,
    },
    SpaceSaving {
        capacity: usize,
    },
    MisraGries {
        capacity: usize,
    },
    HyperLogLog {
        precision: u8,
    },
    HllMap {
        max_keys: usize,
        precision: u8,
    },
    Kll {
        k: usize,
    },
    Composite {
        stages: Vec<PhysicalSketch>,
    },
}
```

## 7.3 Planner job

The planner converts:

```yaml
measure:
  type: distinct_count
  field: dst.ip
groupBy:
  - src.ip
```

into something like:

```text
Candidate plan A:
  HLL per src.ip
  Risk: unbounded number of src.ip keys

Candidate plan B:
  SpaceSaving(src.ip) to track heavy sources
  + HLL per retained src.ip
  Risk: misses low-volume scanners

Candidate plan C:
  HLLMap-like bounded keyed cardinality sketch
  Risk: approximate both key retention and cardinality

Chosen:
  HLLMap if key cardinality is large and memory cap exists.
```

This is exactly where the project becomes interesting. The planner is the differentiator.

---

# 8. Algorithm catalogue and paper/source map

## 8.1 Core algorithms for v0/v1

| Algorithm                                 | Use in FlowSketch                                                         | Why it matters                                                    | Source lineage                                                                                                                                                      |
| ----------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Count-Min Sketch**                      | Approximate per-key packet/byte counts, traffic matrices, point queries   | Simple, mergeable, bounded memory, good for nonnegative updates   | Cormode/Muthukrishnan’s Count-Min Sketch is a sublinear-space frequency table with probabilistic overestimation guarantees.                                         |
| **CountSketch**                           | L2-heavy hitters, signed updates, variance reduction, change signals      | Better for signed/turnstile-like settings and L2-heavy hitters    | CountSketch was introduced by Charikar, Chen, and Farach-Colton for frequent items/frequency moments in data streams.                                               |
| **HyperLogLog**                           | Distinct destination counts, distinct source counts, fan-out/fan-in       | Standard approximate cardinality estimator; compact and mergeable | HyperLogLog estimates count-distinct using much less memory than exact sets; the original paper is Flajolet et al. 2007.                                            |
| **CPC / Theta Sketches**                  | Future higher-accuracy cardinality and set operations                     | Useful for unions/intersections of traffic sets                   | Apache DataSketches documents CPC, Theta, HLL, tuple, frequent-items, and quantiles families.                                                                       |
| **Misra-Gries**                           | Deterministic heavy-hitter candidate generation                           | Simple, deterministic, mergeable variants exist                   | Misra-Gries is one of the earliest heavy-hitter/frequent-item algorithms.                                                                                           |
| **SpaceSaving / frequent-items variants** | Top-k talkers, elephant flows, service pairs                              | Practical heavy-hitter tracking with bounded candidates           | SpaceSaving-family work targets frequency estimation, frequent items, and top-k with limited space; recent variants emphasize mergeability in distributed settings. |
| **KLL / t-digest / quantile sketches**    | Inter-arrival-time distributions, latency-like telemetry where measurable | Needed for distribution summaries, not just counts                | Apache DataSketches includes quantile families including KLL and t-digest-style sketches.                                                                           |

## 8.2 Network-telemetry-specific systems to learn from

| System / paper                                    | What to learn                                                                                                                               | Relevance                                                                                                                      |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Sketchy With a Chance of Adoption**             | Adoption blockers: intent translation, resource allocation, sketch composition, heterogeneous targets                                       | This is almost the design brief for FlowSketch.                                                                                |
| **Compact Data Structures for Network Telemetry** | Current research direction: programmable switches/NICs, compact data structures, memory/compute constraints                                 | Confirms the field is active and relevant to modern telemetry.                                                                 |
| **Survey of sketches in traffic measurement**     | Existing sketch landscape: design, aggregation, decoding, applications, implementation                                                      | Useful for algorithm selection and benchmarking against prior designs.                                                         |
| **Sonata**                                        | High-level query interface that drives traffic collection/analysis; query partitioning between switch and stream processor; use of sketches | Strong inspiration for FlowSketch’s query compiler and runtime.                                                                |
| **PSketch**                                       | eBPF-based in-kernel priority-aware sketching on commodity Linux                                                                            | Shows eBPF sketch monitoring is plausible, but also validates that FlowSketch should generalize beyond one research prototype. |
| **Cilium/Hubble**                                 | Kubernetes-native network observability, local node visibility, Hubble Relay, service map                                                   | FlowSketch should integrate with or complement this, not fight it.                                                             |

## 8.3 What should be copied vs avoided

| Copy                                                   | Avoid                                             |
| ------------------------------------------------------ | ------------------------------------------------- |
| Sonata’s high-level intent idea                        | Requiring programmable switches for the MVP       |
| PSketch’s commodity-Linux/eBPF direction               | Putting the whole planner/runtime in kernel       |
| DataSketches’ production-quality algorithm engineering | Becoming only another algorithm library           |
| Cilium/Hubble’s Kubernetes-native deployment model     | Competing with exact flow visibility/service maps |
| OpenTelemetry’s collector/export model                 | Inventing a proprietary telemetry pipeline        |

---

# 9. Runtime design

## 9.1 Core traits

```rust
pub trait Sketch {
    type Key;
    type Value;
    type Estimate;

    fn update(&mut self, key: Self::Key, value: Self::Value);
    fn estimate(&self, key: &Self::Key) -> Self::Estimate;
    fn merge(&mut self, other: &Self) -> Result<(), SketchError>;
    fn memory_bytes(&self) -> usize;
    fn reset(&mut self);
}

pub trait WindowedSketch {
    fn update_at(&mut self, ts_nanos: u64, event: &FlowEvent);
    fn flush_ready(&mut self, now_nanos: u64) -> Vec<SketchEstimate>;
}
```

## 9.2 Sharding model

High-throughput network telemetry should avoid global locks.

```text
per-core collector
    ↓
per-core sketch shard
    ↓
periodic local flush
    ↓
node-local merge
    ↓
export
```

Implementation:

```rust
pub struct ShardedSketch<S> {
    shards: Vec<S>,
    shard_count: usize,
}

impl<S: Sketch> ShardedSketch<S> {
    pub fn update(&mut self, cpu_id: usize, key: S::Key, value: S::Value) {
        let shard = cpu_id % self.shard_count;
        self.shards[shard].update(key, value);
    }

    pub fn merge_all(&self) -> S {
        // combine compatible sketches
    }
}
```

## 9.3 Windowing

Support three window types:

| Window            | Use                                     |
| ----------------- | --------------------------------------- |
| Tumbling          | Simple periodic summaries               |
| Sliding           | Detection over rolling intervals        |
| Exponential decay | Long-running trend without full history |

MVP should implement:

```text
tumbling window
sliding window as ring of smaller tumbling buckets
```

Example:

```text
60s sliding window, 10s slide
= 6 buckets of 10s each
```

Each bucket has independent sketches. Query result merges the relevant buckets.

## 9.4 Hashing

Hashing is not an implementation detail. It affects accuracy and adversarial behavior.

Implement:

* fixed seeded hash families
* per-query seed isolation
* stable cross-node seeds for mergeability
* optional secret seeds for adversarial environments
* hash-version metadata in exported estimates

```rust
pub struct HashSpec {
    pub family: HashFamily,
    pub seed: u64,
    pub version: u16,
}
```

---

# 10. Collector architecture

## 10.1 v0 collector: offline and userspace

Start with:

| Source                    | Reason                                  |
| ------------------------- | --------------------------------------- |
| pcap file replay          | Deterministic testing                   |
| live AF_PACKET/raw socket | Simple Linux live capture               |
| synthetic generator       | Benchmarking correctness and throughput |

This gives an MVP without kernel complexity.

## 10.2 v1 collector: eBPF tc/XDP

The first serious production collector should be eBPF-based.

Use eBPF to extract minimal packet metadata:

```c
struct flow_event {
    __u64 ts;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u32 bytes;
    __u8  tcp_flags;
    __u32 ifindex;
};
```

Then send to userspace via ring buffer or perf buffer.

Important rule:

> The eBPF program should parse and filter. The userspace runtime should sketch.

Why: eBPF can run safely and efficiently inside the kernel, but it has verifier constraints, finite program complexity limits, map restrictions, and privilege requirements.

## 10.3 Later collectors

| Collector                    | Phase | Notes                                                        |
| ---------------------------- | ----: | ------------------------------------------------------------ |
| Cilium/Hubble receiver       | v1/v2 | Consume existing flow visibility where Cilium exists.        |
| NetFlow/IPFIX/sFlow receiver |    v2 | Important for ISPs and enterprises.                          |
| AF_XDP                       | v2/v3 | Higher performance, higher operational complexity.           |
| DPDK                         |    v3 | For specialized packet-processing shops.                     |
| P4/Tofino                    |    v4 | Research/high-end network hardware.                          |
| SmartNIC/DPU                 |    v4 | NVIDIA BlueField, AMD Pensando, Intel IPU-style future path. |

---

# 11. Planner design

The planner is the core differentiator.

## 11.1 Planner inputs

```yaml
measure:
  type: heavy_hitters
  value: bytes
  limit: 100
error:
  epsilon: 0.001
  delta: 0.01
resources:
  maxMemory: 128MiB
  maxCpuPct: 2
  maxExportSeries: 10000
deployment:
  target: linux-ebpf
```

## 11.2 Planner outputs

```yaml
physicalPlan:
  sketches:
    - id: hh_src_dst_bytes
      algorithm: spacesaving
      capacity: 4096
      shardBy: cpu
      windowBuckets: 6
  expected:
    memoryBytes: 10485760
    cpuCost: medium
    mergeable: true
    exportSeriesUpperBound: 100
    error:
      kind: additive
      epsilon: 0.001
```

## 11.3 Planner decision table

| Query                                     | Preferred plan                                | Why                                       |
| ----------------------------------------- | --------------------------------------------- | ----------------------------------------- |
| `sum(bytes) by src.ip`                    | Count-Min                                     | Simple nonnegative point estimates        |
| `topk(src.ip, bytes)`                     | SpaceSaving or Misra-Gries                    | Need identities, not just point estimates |
| `distinct_count(dst.ip) by src.ip`        | HLLMap / heavy-source + HLL                   | Avoid unbounded HLL per source            |
| `entropy(src.ip)`                         | distribution sketch / UnivMon-like plan       | Entropy needs distributional summary      |
| `change(topk)`                            | paired sketches over current/baseline windows | Compare adjacent windows                  |
| `traffic_matrix(src.service,dst.service)` | Count-Min if huge, exact if low-cardinality   | Service labels may be manageable          |

## 11.4 Accuracy contracts

Every query should expose:

```text
algorithm
memory budget
window size
estimated value
error model
confidence level if applicable
known failure modes
```

Example Prometheus labels:

```text
flowsketch_query_estimate{
  query="suspected_scanners",
  algorithm="hllmap",
  error_kind="relative",
  window="60s"
} 7132
```

Approximation must be explicit because production operators need to know whether the number is exact, approximate, biased high, biased low, or candidate-based.

---

# 12. Export APIs

## 12.1 Prometheus endpoint

Expose `/metrics`.

Prometheus’s text exposition format is line-oriented over HTTP, supports Counter, Gauge, Histogram, Summary, and Untyped primitives, and is intentionally easy to assemble for minimal cases.

Example:

```text
# HELP flowsketch_top_bytes Estimated bytes for heavy hitter flow
# TYPE flowsketch_top_bytes gauge
flowsketch_top_bytes{
  query="top_talkers",
  src_ip="10.0.1.15",
  dst_ip="10.0.2.20",
  protocol="tcp",
  algorithm="spacesaving",
  window="60s"
} 18422391

# HELP flowsketch_distinct_dst Estimated distinct destinations per source
# TYPE flowsketch_distinct_dst gauge
flowsketch_distinct_dst{
  query="suspected_scanners",
  src_ip="10.0.1.50",
  algorithm="hll",
  window="60s"
} 9231
```

## 12.2 OTLP metrics exporter

OpenTelemetry Collector config is built from receivers, processors, exporters, connectors, extensions, and service pipelines; that structure is exactly why FlowSketch should export OTLP instead of inventing a pipeline.

FlowSketch config:

```yaml
export:
  otlp:
    endpoint: http://otel-collector.observability.svc:4317
    protocol: grpc
    temporality: delta
```

OTel Collector config:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  batch:
  memory_limiter:
    check_interval: 5s
    limit_mib: 512

exporters:
  prometheusremotewrite:
    endpoint: http://mimir/api/v1/push
  otlp/datadog:
    endpoint: datadog-agent.default.svc:4317

service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [prometheusremotewrite, otlp/datadog]
```

## 12.3 Native gRPC API

Use native gRPC for control and raw sketch estimates.

```proto
syntax = "proto3";

package flowsketch.v1;

service FlowSketchControl {
  rpc ApplyQuery(ApplyQueryRequest) returns (ApplyQueryResponse);
  rpc DeleteQuery(DeleteQueryRequest) returns (DeleteQueryResponse);
  rpc ListQueries(ListQueriesRequest) returns (ListQueriesResponse);
  rpc ExplainQuery(ExplainQueryRequest) returns (ExplainQueryResponse);
  rpc StreamEstimates(StreamEstimatesRequest) returns (stream SketchEstimate);
}

message ApplyQueryRequest {
  string name = 1;
  string yaml = 2;
  bool dry_run = 3;
}

message ExplainQueryResponse {
  string logical_plan = 1;
  string physical_plan = 2;
  uint64 estimated_memory_bytes = 3;
  string error_contract = 4;
}
```

The `ExplainQuery` endpoint is essential. It gives the operator confidence before deployment.

## 12.4 Kafka / ClickHouse export

For larger users:

```yaml
export:
  kafka:
    brokers:
      - kafka-1:9092
    topic: flowsketch.estimates
    format: protobuf
```

This lets Datadog/Splunk/Elastic/Kentik-style platforms consume sketch results as events, not just metrics.

---

# 13. OpenTelemetry integration plan

## 13.1 Two integration modes

### Mode A: FlowSketch as OTLP producer

```text
FlowSketch agent
    ↓ OTLP metrics/logs
OpenTelemetry Collector / Grafana Alloy / Datadog Collector
    ↓
backend
```

This is the simplest and should be the default.

### Mode B: FlowSketch as OpenTelemetry Collector receiver

Later, implement a custom OTel receiver:

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

This makes FlowSketch embeddable into existing OTel collector distributions.

## 13.2 Semantic mapping

Use OTel metric names like:

```text
network.flowsketch.bytes.estimated
network.flowsketch.packets.estimated
network.flowsketch.distinct_destinations.estimated
network.flowsketch.heavy_hitters.rank
network.flowsketch.entropy.estimated
network.flowsketch.change_score
```

Resource attributes:

```text
service.name = "flowsketch-agent"
host.name
k8s.cluster.name
k8s.node.name
k8s.namespace.name
k8s.pod.name
k8s.pod.uid
cloud.provider
cloud.region
```

Metric attributes:

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

Be conservative with IP labels. Exporting raw IPs as Prometheus labels can create its own cardinality explosion.

## 13.3 Cardinality guardrails

FlowSketch must have export caps:

```yaml
export:
  maxSeriesPerQuery: 1000
  redact:
    ipMode: hash_prefix
    prefixLengthV4: 24
  dropLabels:
    - src.port
```

This is non-negotiable. An approximate high-cardinality telemetry tool must not create a high-cardinality metrics disaster.

---

# 14. Grafana integration

Grafana Labs would care if FlowSketch exports through **Prometheus** or **OTLP**.

Grafana Alloy is an open-source telemetry collector, an OpenTelemetry Collector distribution with built-in Prometheus pipelines and native support for Loki, Pyroscope, and other observability backends.

## 14.1 Grafana Alloy config

```hcl
otelcol.receiver.otlp "flowsketch" {
  grpc {
    endpoint = "0.0.0.0:4317"
  }

  http {
    endpoint = "0.0.0.0:4318"
  }

  output {
    metrics = [otelcol.processor.batch.default.input]
    logs    = [otelcol.processor.batch.default.input]
  }
}

otelcol.processor.batch "default" {
  output {
    metrics = [otelcol.exporter.otlp.grafana.input]
    logs    = [otelcol.exporter.otlp.grafana.input]
  }
}

otelcol.exporter.otlp "grafana" {
  client {
    endpoint = "grafana-otlp-endpoint:4317"
  }
}
```

## 14.2 Grafana dashboard package

Ship official dashboards:

| Dashboard             | Panels                                                   |
| --------------------- | -------------------------------------------------------- |
| Network Heavy Hitters | top src/dst pairs, bytes, packets, rank, error           |
| Scanner Detection     | distinct destinations by source, threshold events        |
| Service Fan-Out       | namespace/service fan-out over time                      |
| DDoS Signals          | entropy, source cardinality, heavy hitters               |
| Agent Health          | CPU, dropped events, ring buffer pressure, sketch memory |
| Accuracy/Resource     | query memory, sketch width/depth, export series count    |

## 14.3 Why Grafana could adopt it

Grafana does not need to own the agent. It only needs:

* OTLP ingest
* Prometheus scrape
* dashboards
* alert rules
* Alloy config examples

That makes adoption low-friction.

---

# 15. Datadog integration

Datadog already has OpenTelemetry support, network monitoring products, custom integrations, OpenMetrics checks, and a recommended Datadog OpenTelemetry Collector path. The Datadog docs expose OpenTelemetry setup paths, semantic mapping, integrations, and ways to build Agent-based integrations, dashboards, monitors, and Cloud SIEM rules.

## 15.1 Datadog ingestion options

| Option                              | Difficulty | Notes                                             |
| ----------------------------------- | ---------: | ------------------------------------------------- |
| OTLP metrics to Datadog Collector   |        Low | Best first path                                   |
| OpenMetrics scrape by Datadog Agent |        Low | Good for self-managed clusters                    |
| Datadog Agent integration           |     Medium | Best if Datadog wants first-class product support |
| Cloud SIEM detection rules          |     Medium | Useful for scanner/exfiltration signals           |
| Datadog Observability Pipelines     |     Medium | Useful for routing/transforming FlowSketch events |

## 15.2 Datadog-facing config

FlowSketch:

```yaml
export:
  otlp:
    endpoint: http://datadog-otel-collector.default.svc:4317
    protocol: grpc
  tags:
    env: prod
    team: platform
    source: flowsketch
```

Datadog-style metric examples:

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

Again: raw IP tags should be capped or hashed.

---

# 16. Kubernetes integration

## 16.1 Deployment model

Use a DaemonSet:

```text
one FlowSketch agent per node
    ↓
node-local packet observation
    ↓
node-local sketches
    ↓
cluster gateway merges estimates
    ↓
OTel/Prometheus export
```

## 16.2 Components

```text
flowsketch-agent DaemonSet
flowsketch-gateway Deployment
flowsketch-operator Deployment
SketchQuery CRD
Helm chart
Grafana dashboards
PrometheusRule templates
```

## 16.3 CRD

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

## 16.4 Operator responsibilities

| Responsibility   | Description                                             |
| ---------------- | ------------------------------------------------------- |
| Validate queries | Reject unsafe/unbounded query shapes                    |
| Explain plans    | Attach physical plan and estimated memory as CRD status |
| Roll out configs | Push query config to agents                             |
| Track health     | Agent readiness, dropped events, sketch pressure        |
| Manage gateways  | Cluster-level merge/aggregation                         |
| Enforce limits   | Namespace/team-level memory and series budgets          |

---

# 17. Distributed aggregation

## 17.1 Why distributed merge matters

A node-local agent is useful, but Apache-scale value comes from network-wide queries:

```text
top talkers across cluster
distinct destinations across all nodes
service-to-service traffic matrix
cluster-wide entropy shift
```

Many sketches are mergeable. Count-Min, CountSketch, and HyperLogLog-style sketches can be combined when configured compatibly; Apache DataSketches also emphasizes mergeability and cross-language compatible binary representations for production use.

## 17.2 Merge architecture

```text
agent on node A ─┐
agent on node B ─┼─> flowsketch-gateway ──> OTLP / Prometheus / Kafka
agent on node C ─┘
```

## 17.3 Compatibility requirements

Sketches can only merge if:

```text
same algorithm
same hash family
same seeds
same width/depth/precision
same window boundaries
same key encoding
same version
```

Represent this explicitly:

```rust
pub struct SketchCompatibility {
    pub algorithm: String,
    pub version: u16,
    pub hash_family: String,
    pub seed: u64,
    pub params_hash: u64,
}
```

If incompatible, reject merge and emit health metrics.

---

# 18. Storage design

FlowSketch should not become a database.

But it needs short-term local state:

| State                | Storage                                                         |
| -------------------- | --------------------------------------------------------------- |
| Active sketches      | memory                                                          |
| Config               | file / Kubernetes ConfigMap / CRD                               |
| Crash recovery       | optional local snapshot                                         |
| Debug samples        | bounded ring buffer                                             |
| Historical estimates | external backend: Prometheus, Mimir, ClickHouse, Kafka, Datadog |

## 18.1 Snapshot format

Use a versioned binary format:

```text
magic: FSK1
version: u16
algorithm_id: u16
hash_spec
params
window_start
window_end
payload_len
payload
checksum
```

Do this early. Stable serialization is necessary for distributed merge, tests, and future language bindings.

---

# 19. Security and privacy model

## 19.1 Default privacy posture

Default behavior:

```text
no payload capture
no DNS content capture unless explicitly enabled
no full packet storage
bounded debug sampling
IP hashing available
prefix aggregation available
label allowlist required
```

## 19.2 RBAC

Kubernetes permissions should be minimal:

| Permission                              | Why                                                                    |
| --------------------------------------- | ---------------------------------------------------------------------- |
| Read pods/namespaces/services/endpoints | Metadata enrichment                                                    |
| Read nodes                              | Node identity                                                          |
| Watch SketchQuery CRDs                  | Query config                                                           |
| No secret read                          | Should not need secrets except exporter credentials via mounted secret |

## 19.3 Runtime safety

Expose health metrics:

```text
flowsketch_agent_dropped_events_total
flowsketch_agent_ring_buffer_utilization
flowsketch_agent_cpu_seconds_total
flowsketch_agent_memory_bytes
flowsketch_agent_sketch_memory_bytes
flowsketch_agent_export_failures_total
flowsketch_agent_queries_active
flowsketch_agent_queries_rejected_total
```

---

# 20. MVP implementation phases

## Phase 0 — Scope lock

**Goal:** prevent the project from becoming too broad.

### Deliverables

* Project charter
* Query primitives list
* Supported algorithms list
* Supported export paths
* Explicit non-goals

### Non-goals for first 6 months

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

---

## Phase 1 — Core algorithm crate

**Goal:** build correct, tested sketch primitives.

### Implement

```text
flowsketch-core
flowsketch-algos
```

Algorithms:

* Count-Min Sketch
* CountSketch
* HyperLogLog
* SpaceSaving
* Misra-Gries
* simple exact counter for baseline comparison
* optional KLL later

### Tests

| Test            | Description                                             |
| --------------- | ------------------------------------------------------- |
| Unit tests      | update/query/merge                                      |
| Property tests  | merge equivalence, reset, serialization                 |
| Golden tests    | deterministic output with fixed seeds                   |
| Error tests     | synthetic distributions: uniform, Zipf, adversarial-ish |
| Benchmark tests | update throughput, memory footprint                     |

### Acceptance criteria

```text
>5M updates/sec/core in userspace synthetic benchmark
stable serialization format
merge compatibility checks
documented error model for each algorithm
```

---

## Phase 2 — Offline replay prototype

**Goal:** prove useful answers from traffic traces.

### Implement

```text
flowsketch-pcap
flowsketch-cli
basic query YAML
Prometheus text output
```

CLI:

```bash
flowsketch replay trace.pcap --query top-talkers.yaml
flowsketch explain top-talkers.yaml
flowsketch bench --algo count-min --events 10000000
```

Example output:

```text
QUERY top_talkers window=60s algorithm=spacesaving
rank src_ip        dst_ip        estimate_bytes
1    10.0.1.10    10.0.2.50    812312381
2    10.0.1.11    10.0.2.51    553123900
```

### Acceptance criteria

```text
reads pcap
extracts IPv4/IPv6/TCP/UDP
runs 3 useful queries
exports Prometheus text
has reproducible benchmark suite
```

This phase is where you avoid building a complicated agent before you know the query model is useful.

---

## Phase 3 — Userspace live agent

**Goal:** live passive monitoring without eBPF yet.

### Implement

```text
flowsketch-agent
AF_PACKET/raw socket input
HTTP /metrics endpoint
HTTP /healthz
config reload
```

Agent config:

```yaml
agent:
  nodeName: node-a
  interfaces:
    - eth0
  capture:
    mode: af_packet
  resourceLimits:
    maxMemory: 256MiB
    maxCpuPct: 5

queries:
  - file: /etc/flowsketch/queries/top-talkers.yaml

export:
  prometheus:
    listen: 0.0.0.0:9464
```

### Acceptance criteria

```text
runs as systemd service
runs in Docker with host networking
scrapable by Prometheus
safe failure mode
bounded memory
```

---

## Phase 4 — OTLP exporter

**Goal:** make it usable by real observability teams.

### Implement

```text
flowsketch-otel
OTLP metrics exporter
OTLP logs/events exporter for anomalies
batching
retry/backoff
resource attributes
```

The OpenTelemetry Collector already expects pipelines made of receivers, processors, and exporters, and supports OTLP over gRPC/HTTP in common configurations.

### Acceptance criteria

```text
exports to OpenTelemetry Collector
exports to Grafana Alloy
exports to Datadog OTel path
resource attributes follow OTel conventions where practical
```

---

## Phase 5 — Kubernetes-native MVP

**Goal:** make adoption look normal for platform teams.

### Implement

```text
Helm chart
DaemonSet
ServiceMonitor
SketchQuery CRD
basic operator
Kubernetes metadata enricher
```

Deployment:

```bash
helm install flowsketch flowsketch/flowsketch \
  --namespace observability \
  --set export.otlp.endpoint=http://otel-collector:4317
```

### Acceptance criteria

```text
one agent per node
pod/service/namespace enrichment
Prometheus scrape works
OTLP export works
SketchQuery CRD works
Grafana dashboard package works
```

---

## Phase 6 — eBPF collector

**Goal:** credible production packet collection.

### Implement

```text
flowsketch-ebpf
tc ingress hook first
XDP optional
ring buffer export
kernel capability checks
fallback to userspace mode
```

Design:

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

PSketch is a recent example showing that eBPF-based sketch monitoring on commodity Linux is plausible; it reports top-k flow detection on 10 Gbps traces with low throughput degradation.

### Acceptance criteria

```text
loads on supported kernels
fails closed if verifier rejects program
does not alter packets
overhead benchmarked
supports tc ingress
supports IPv4/IPv6/TCP/UDP
```

---

## Phase 7 — Cluster gateway and distributed merge

**Goal:** network-wide approximate queries.

### Implement

```text
flowsketch-gateway
agent-to-gateway gRPC
sketch snapshot transport
merge compatibility validation
cluster-level estimates
```

Gateway API:

```proto
service FlowSketchIngest {
  rpc PushSketch(PushSketchRequest) returns (PushSketchResponse);
  rpc StreamSketches(stream SketchFrame) returns (PushSketchResponse);
}
```

### Acceptance criteria

```text
cluster-wide top-k
cluster-wide distinct counts
node-level and cluster-level exports
merge errors observable
bounded gateway memory
```

---

## Phase 8 — Query planner v1

**Goal:** stop forcing users to think in algorithms.

### Implement

```text
logical IR
physical IR
memory estimator
error estimator
query explain
query rejection
```

Example:

```bash
flowsketch explain suspected-scanners.yaml
```

Output:

```text
Logical query:
  group by src.ip
  estimate distinct_count(dst.ip)
  window 60s slide 10s

Physical plan:
  HLLMap(precision=12, max_keys=4096)
  6 window buckets
  estimated memory: 18.7 MiB
  export series upper bound: 500

Warnings:
  raw src.ip labels may create high series cardinality
  use ipMode=hash_prefix or maxSeries cap for Prometheus
```

### Acceptance criteria

```text
planner chooses algorithms
planner estimates memory
planner rejects unsafe plans
explain output is useful to operators
```

This is a major project milestone. It moves FlowSketch from “tool” to “runtime.”

---

## Phase 9 — Advanced integrations

**Goal:** become ecosystem infrastructure.

### Add

| Integration                           | Why                                               |
| ------------------------------------- | ------------------------------------------------- |
| Cilium/Hubble receiver                | Avoid duplicate packet capture in Cilium clusters |
| OpenTelemetry Collector receiver      | Embed into collector distributions                |
| Grafana Alloy component               | First-class Grafana path                          |
| Datadog Agent/OpenMetrics integration | First-class Datadog path                          |
| ClickHouse sink                       | Large event analytics                             |
| Kafka sink                            | Security/event pipelines                          |
| Terraform/Helm modules                | Enterprise adoption                               |
| PrometheusRule templates              | Alerting out of the box                           |

Cilium/Hubble already gives node, cluster, and multi-cluster visibility, flow filtering, and service maps; FlowSketch should use that ecosystem where present rather than duplicate all visibility logic.

---

## Phase 10 — Advanced backends

Only after v1.

| Backend            | Why later                                          |
| ------------------ | -------------------------------------------------- |
| AF_XDP             | More performance, more complexity                  |
| DPDK               | Too invasive for normal users                      |
| P4                 | Great research story, not MVP                      |
| SmartNIC/DPU       | Vendor partnerships needed                         |
| WASM plugin engine | Useful but creates security/reliability complexity |

---

# 21. Public API surface

## 21.1 CLI

```bash
flowsketch agent --config /etc/flowsketch/config.yaml
flowsketch replay trace.pcap --query query.yaml
flowsketch explain query.yaml
flowsketch validate query.yaml
flowsketch status
flowsketch top --query top-talkers --window 60s
flowsketch export snapshot --query top-talkers
flowsketch bench --profile 10g
```

## 21.2 HTTP API

```text
GET  /healthz
GET  /readyz
GET  /metrics
GET  /v1/queries
POST /v1/queries
GET  /v1/queries/{name}/explain
GET  /v1/queries/{name}/estimates
DELETE /v1/queries/{name}
```

## 21.3 gRPC API

Use gRPC for:

* streaming estimates
* pushing snapshots
* gateway aggregation
* control-plane sync

## 21.4 Kubernetes API

```text
SketchQuery
SketchQueryStatus
FlowSketchAgent
FlowSketchGateway
```

`SketchQueryStatus` should include:

```yaml
status:
  accepted: true
  physicalPlan:
    algorithm: hllmap
    memoryBytes: 19608320
  warnings:
    - raw IP labels are capped to 500 series
  lastApplied: "2026-07-03T12:00:00Z"
```

---

# 22. Example queries to ship

## 22.1 Top talkers

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

## 22.2 Suspected scanners

```yaml
name: suspected_scanners
window:
  size: 60s
  slide: 10s
groupBy:
  - src.ip
measure:
  type: distinct_count
  field: dst.ip
alertIf:
  gt: 5000
```

## 22.3 Namespace fan-out

```yaml
name: namespace_fanout
window:
  size: 5m
  slide: 30s
groupBy:
  - k8s.namespace.name
measure:
  type: distinct_count
  field: dst.ip
```

## 22.4 Service traffic matrix

```yaml
name: service_traffic_matrix
window:
  size: 60s
  slide: 10s
groupBy:
  - src.service
  - dst.service
measure:
  type: sum
  field: bytes
```

## 22.5 DDoS entropy shift

```yaml
name: ddos_entropy_shift
window:
  size: 30s
  slide: 5s
groupBy:
  - dst.ip
measure:
  type: entropy
  field: src.ip
change:
  baseline: 5m
```

---

# 23. Benchmarking plan

## 23.1 Correctness benchmarks

Datasets:

```text
synthetic uniform
synthetic Zipf
synthetic scanner
synthetic DDoS
CAIDA traces where legally available
MAWI traces where legally available
pcap fixtures
```

Metrics:

| Metric             | Meaning                |
| ------------------ | ---------------------- |
| ARE                | average relative error |
| AAE                | average absolute error |
| precision@k        | top-k correctness      |
| recall@k           | missed heavy hitters   |
| false positives    | scanner/DDoS signals   |
| false negatives    | missed anomalies       |
| update throughput  | events/sec/core        |
| memory/query       | bytes                  |
| export cardinality | time series emitted    |
| dropped events     | collector pressure     |

## 23.2 Systems benchmarks

Targets:

```text
1 Gb/s: easy MVP
10 Gb/s: credible v1
25/40 Gb/s: serious infrastructure
100 Gb/s: future/DPDK/P4/SmartNIC tier
```

Test matrix:

| Mode            | Target                        |
| --------------- | ----------------------------- |
| pcap replay     | correctness and repeatability |
| AF_PACKET       | simple live baseline          |
| eBPF tc         | production Linux path         |
| XDP             | higher-performance Linux path |
| Hubble receiver | Kubernetes/Cilium path        |

## 23.3 Public benchmark artifacts

Ship:

```text
benchmark harness
synthetic trace generator
ground-truth exact aggregator
standard query suite
results dashboard
reproducible Docker environment
```

Implemented v0 harness:

```bash
flowsketch bench --trace /data/caida-or-mawi.pcap \
  --query examples/queries/top-talkers.yaml \
  --profile all
```

This reports measured parser/runtime throughput and projects the CPU cores
needed for 1/10/25/40/100 Gb/s at the trace's observed average packet size.
It also reports direct projected L3 Gb/s per core. It does not replace live
NIC validation. See `benchmarks/README.md`.

This is crucial for trust. Operators will not install this based on theory alone.

---

# 24. What Datadog, Grafana, and others would need

## 24.1 Datadog

Datadog adoption path:

```text
FlowSketch OTLP metrics
    ↓
Datadog OTel Collector / Agent integration
    ↓
Datadog dashboards + monitors + Cloud SIEM rules
```

Datadog would want:

* stable metric names
* bounded tag cardinality
* Datadog dashboard JSON
* monitor templates
* OpenMetrics integration option
* Cloud SIEM rule examples
* Kubernetes tags
* service ownership tags

## 24.2 Grafana Labs

Grafana adoption path:

```text
FlowSketch OTLP / Prometheus
    ↓
Grafana Alloy
    ↓
Mimir / Prometheus / Loki / Grafana dashboards
```

Grafana Alloy already positions itself as a unified telemetry collector with OTel and Prometheus pipelines, which is exactly the compatibility layer FlowSketch should target.

Grafana would want:

* official dashboard bundle
* Alloy example configs
* Prometheus recording rules
* Mimir-compatible metrics
* Loki anomaly event export
* Helm chart
* Kubernetes dashboards

## 24.3 Cilium / Isovalent / Cisco

Adoption path:

```text
Cilium/Hubble flow visibility
    ↓
FlowSketch Hubble receiver
    ↓
approximate high-cardinality summaries
```

They would care if FlowSketch becomes:

* a Hubble extension
* a Cilium-compatible summarization backend
* an approximate query layer over flows
* a way to reduce flow export volume

## 24.4 Cloud providers

Adoption path:

```text
node/host agent
or
VPC flow-log pre-aggregation
or
managed Kubernetes telemetry add-on
```

They would care about:

* reducing telemetry volume
* cheaper high-cardinality queries
* tenant-safe aggregation
* privacy-preserving summaries
* DDoS/security signals

---

# 25. Engineering effort estimate

## 25.1 Solo founder / small OSS start

| Milestone                         | Time estimate |                               People |
| --------------------------------- | ------------: | -----------------------------------: |
| Core sketches + replay CLI        |    1–2 months |            1 strong systems engineer |
| Live userspace agent + Prometheus |    2–3 months |                                  1–2 |
| OTLP export + basic dashboards    |       1 month |                                    1 |
| Kubernetes DaemonSet + metadata   |    2–3 months |                                  1–2 |
| eBPF collector                    |    3–6 months |              1 eBPF-capable engineer |
| Distributed gateway               |    2–4 months |                                  1–2 |
| Planner v1                        |    3–6 months | 1 strong algorithms/systems engineer |

A credible public MVP is probably **4–6 months** for a very strong small team.

A production-trustworthy v1 is more like **12–18 months**.

Apache-scale maturity is **multi-year**.

## 25.2 Difficulty by subsystem

| Subsystem                      | Difficulty |
| ------------------------------ | ---------: |
| Basic sketch algorithms        |       4/10 |
| Correct merge/window semantics |       7/10 |
| Query planner                  |       8/10 |
| Prometheus export              |       3/10 |
| OTLP export                    |       5/10 |
| Kubernetes metadata            |       6/10 |
| eBPF collector                 |       8/10 |
| High-throughput reliability    |       8/10 |
| Distributed merge              |       7/10 |
| Enterprise trust/security      |       9/10 |

---

# 26. The minimum credible v0

The first release should include exactly this:

```text
1. Rust sketch runtime
2. pcap replay
3. live Linux userspace capture
4. Count-Min, CountSketch, HLL, SpaceSaving
5. YAML query config
6. top talkers
7. distinct destinations per source
8. service/namespace fan-out if Kubernetes metadata available
9. Prometheus /metrics
10. OTLP metrics exporter
11. flowsketch explain
12. benchmarks against exact ground truth
```

Do **not** wait for eBPF to release the first version.

The first proof is:

> “Given real or replayed traffic, FlowSketch answers useful high-cardinality questions with bounded memory and exports them into existing observability systems.”

---

# 27. What makes it Apache-scale

The Apache-scale version has to be more than an agent.

It needs:

| Layer             | Apache-scale surface                                           |
| ----------------- | -------------------------------------------------------------- |
| Algorithm runtime | Many sketch implementations, stable traits, serialization      |
| Query planner     | Vendor-neutral approximate telemetry compiler                  |
| Backends          | pcap, AF_PACKET, eBPF, Hubble, NetFlow/IPFIX, AF_XDP, DPDK, P4 |
| Integrations      | OTel, Prometheus, Grafana, Datadog, Kafka, ClickHouse          |
| Kubernetes        | CRDs, operator, Helm, dashboards                               |
| Governance        | pluggable algorithms, pluggable exporters, conformance suite   |
| Benchmarks        | public, reproducible, vendor-neutral                           |
| Spec              | sketch query language + binary sketch snapshot format          |

The most defensible Apache identity is:

> **FlowSketch: the open standard runtime for approximate network telemetry.**

---

# 28. Why this is genuinely related to Jelani Nelson’s world

Jelani Nelson’s Berkeley page lists his role in the Berkeley theory group and teaching/notes on sketching and streaming algorithms, including “Sketching Algorithms” and “Sketching Algorithms for Big Data.”

FlowSketch is downstream of that theoretical lineage:

```text
streaming/sketching theory
    ↓
Count-Min / CountSketch / HLL / heavy hitters / dimensionality reduction
    ↓
network telemetry algorithms
    ↓
FlowSketch production runtime
```

But the implementation project is **systems engineering**, not pure theory.

The project’s hard parts are:

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

So the right mental model is:

> Jelani Nelson-style research gives the mathematical foundation. FlowSketch would be the production systems layer that makes that family of ideas usable by SRE, network, security, and observability teams.

---

# 29. Biggest risks

## Risk 1: It becomes just another sketch crate

Mitigation:

```text
Lead with agent + query planner + OTel/Prometheus export.
Keep raw algorithm APIs secondary.
```

## Risk 2: Prometheus cardinality explosion

Mitigation:

```text
Hard export caps.
Hash/prefix IP labels.
Default top-k only.
Reject unsafe queries.
```

## Risk 3: eBPF complexity eats the project

Mitigation:

```text
Start with pcap + userspace live capture.
Make eBPF a collector backend, not the whole system.
```

## Risk 4: Cilium/Datadog/Kentik absorbs the idea

Mitigation:

```text
Be neutral, portable, and backend-agnostic.
Integrate with them instead of competing head-on.
Own the query language, planner, sketch runtime, and conformance suite.
```

## Risk 5: Approximate results are not trusted

Mitigation:

```text
Expose error contracts.
Expose algorithm metadata.
Ship exact-vs-approx benchmarks.
Provide explain plans.
Show resource savings.
```

---

# 30. My concrete build order

## Build this first

```text
flowsketch-core
flowsketch-algos
flowsketch-pcap
flowsketch-cli
flowsketch-prometheus
```

Then:

```text
flowsketch-agent
flowsketch-otel
flowsketch-k8s
```

Then:

```text
flowsketch-ebpf
flowsketch-gateway
flowsketch-planner
```

Only then:

```text
Hubble receiver
Datadog integration
Grafana Alloy integration
ClickHouse/Kafka
AF_XDP
P4/SmartNIC
```

---

# 31. Final verdict

This is hard, but it is a coherent project.

The defensible version is not:

> “We implemented sketches.”

It is:

> “We built the missing production runtime that compiles network observability intent into bounded-memory sketch execution and exports the results through OpenTelemetry and Prometheus.”

That has a realistic path to production use, a real research lineage, a clear OSS gap, and enough surface area to plausibly become Apache-scale.
