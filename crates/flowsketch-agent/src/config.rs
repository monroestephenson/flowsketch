//! Agent configuration file (YAML).
//!
//! ```yaml
//! agent:
//!   nodeName: node-a
//!   listen: 127.0.0.1:9464
//!   seed: 0
//!   flushIntervalMs: 1000
//!   runtimeShards: 4
//!   runtimeBatchSize: 4096
//!   cpuAffinity:              # optional, Linux only
//!     captureCpu: 0
//!     runtimeCpus: [1, 2, 3, 4]
//!   source:
//!     kind: pcap            # pcap | af_packet | ebpf
//!     path: demo.pcap       # pcap: file to replay
//!     interface: eth0       # af_packet: interface to sniff
//!     ringBlockSizeBytes: 1048576
//!     ringBlockCount: 64
//!     blockRetireTimeoutMs: 64
//! queries:
//!   - file: examples/queries/top-talkers.yaml
//! ```

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use flowsketch_core::hash::HashSpec;
use flowsketch_ir::parse_query_yaml;
use flowsketch_planner::{plan, Plan};

use crate::AgentError;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeShardStrategy {
    Flow,
    RoundRobin,
}

/// Optional Linux CPU placement for the capture thread and each long-lived
/// runtime worker. CPU identifiers are Linux logical CPU numbers.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CpuAffinityConfig {
    #[serde(rename = "captureCpu", alias = "capture_cpu")]
    pub capture_cpu: usize,
    #[serde(rename = "runtimeCpus", alias = "runtime_cpus")]
    pub runtime_cpus: Vec<usize>,
}

/// Where packets come from.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConfig {
    /// Replay a pcap file, then keep serving results (demo/test mode).
    Pcap { path: PathBuf },
    /// Live capture from a network interface via an AF_PACKET raw socket
    /// (Linux; requires CAP_NET_RAW).
    AfPacket {
        interface: String,
        /// Size of each TPACKET_V3 ring block. Power of two and at least
        /// 64 KiB so it is valid on Linux systems with page sizes up to
        /// 64 KiB.
        #[serde(
            default = "default_ring_block_size_bytes",
            rename = "ringBlockSizeBytes",
            alias = "ring_block_size_bytes"
        )]
        ring_block_size_bytes: u32,
        /// Number of blocks in the memory-mapped receive ring.
        #[serde(
            default = "default_ring_block_count",
            rename = "ringBlockCount",
            alias = "ring_block_count"
        )]
        ring_block_count: u32,
        /// Maximum time the kernel may hold a partially filled block before
        /// handing it to userspace.
        #[serde(
            default = "default_block_retire_timeout_ms",
            rename = "blockRetireTimeoutMs",
            alias = "block_retire_timeout_ms"
        )]
        block_retire_timeout_ms: u32,
    },
    /// Linux tc ingress eBPF collector. Loading requires BPF and network
    /// administration capabilities. Fallback is explicit so verifier or
    /// attachment failures are never silently hidden.
    Ebpf {
        interface: String,
        #[serde(rename = "objectPath", alias = "object_path")]
        object_path: PathBuf,
        #[serde(
            default = "default_ebpf_ring_buffer_bytes",
            rename = "ringBufferBytes",
            alias = "ring_buffer_bytes"
        )]
        ring_buffer_bytes: u32,
        #[serde(
            default,
            rename = "fallbackToAfPacket",
            alias = "fallback_to_af_packet"
        )]
        fallback_to_af_packet: bool,
    },
}

const MIN_RING_BLOCK_SIZE_BYTES: u32 = 64 * 1024;
const MAX_RING_BLOCK_SIZE_BYTES: u32 = 16 * 1024 * 1024;
const MAX_RING_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_EBPF_RING_BYTES: u32 = 64 * 1024;
const MAX_EBPF_RING_BYTES: u32 = 1024 * 1024 * 1024;
const MAX_LINUX_CPU_ID: usize = 1023;

pub(crate) const fn default_ring_block_size_bytes() -> u32 {
    1024 * 1024
}

pub(crate) const fn default_ring_block_count() -> u32 {
    64
}

pub(crate) const fn default_block_retire_timeout_ms() -> u32 {
    64
}

const fn default_ebpf_ring_buffer_bytes() -> u32 {
    16 * 1024 * 1024
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub node_name: String,
    pub listen: String,
    pub seed: u64,
    pub flush_interval_ms: u64,
    /// Independent mergeable query engines used for parallel batch updates.
    pub runtime_shards: usize,
    /// Maximum events dispatched to the runtime worker pool at once.
    pub runtime_batch_size: usize,
    pub runtime_shard_strategy: RuntimeShardStrategy,
    pub cpu_affinity: Option<CpuAffinityConfig>,
    pub source: SourceConfig,
    pub query_files: Vec<PathBuf>,
    /// OTLP export, if configured.
    pub otlp: Option<flowsketch_otel::OtlpConfig>,
    /// Snapshot push to a cluster gateway, if configured.
    pub gateway: Option<flowsketch_gateway::PushConfig>,
}

impl AgentConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self, AgentError> {
        let raw: RawConfig =
            serde_yaml::from_str(yaml).map_err(|e| AgentError::Config(e.to_string()))?;
        if raw.queries.is_empty() {
            return Err(AgentError::Config(
                "agent config must list at least one query file".into(),
            ));
        }
        let runtime_shards = raw.agent.runtime_shards.unwrap_or(1);
        if !(1..=256).contains(&runtime_shards) {
            return Err(AgentError::Config(
                "agent.runtimeShards must be between 1 and 256".into(),
            ));
        }
        let runtime_batch_size = raw.agent.runtime_batch_size.unwrap_or(4_096);
        if !(1..=65_536).contains(&runtime_batch_size) {
            return Err(AgentError::Config(
                "agent.runtimeBatchSize must be between 1 and 65536".into(),
            ));
        }
        let cpu_affinity = raw.agent.cpu_affinity.clone();
        validate_cpu_affinity(cpu_affinity.as_ref(), runtime_shards)?;
        validate_source(&raw.agent.source)?;
        let export = raw.export.unwrap_or_default();
        let otlp = export.otlp.map(|o| {
            let interval_ms = o.interval_ms.unwrap_or(5_000).max(100);
            flowsketch_otel::OtlpConfig {
                endpoint: o.endpoint,
                interval_ms,
            }
        });
        if let Some(o) = &otlp {
            if !o.endpoint.starts_with("http://") {
                return Err(AgentError::Config(format!(
                    "export.otlp.endpoint must be http:// (got {:?}); point it at a local \
                     OpenTelemetry Collector",
                    o.endpoint
                )));
            }
        }
        let gateway = export.gateway.map(|g| flowsketch_gateway::PushConfig {
            endpoint: g.endpoint,
            interval_ms: g.interval_ms.unwrap_or(5_000).max(100),
        });
        if let Some(g) = &gateway {
            if !g.endpoint.starts_with("http://") {
                return Err(AgentError::Config(format!(
                    "export.gateway.endpoint must be http:// (got {:?}); point it at a \
                     flowsketch gateway",
                    g.endpoint
                )));
            }
            // The gateway keys snapshots by node name. Agents left on the
            // default would all push as "unknown" and overwrite each other,
            // so a unique nodeName is mandatory in gateway mode.
            if raw
                .agent
                .node_name
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(AgentError::Config(
                    "agent.nodeName must be set to a unique value when export.gateway is \
                     configured; the gateway keys snapshots by node name and agents sharing \
                     the default would overwrite each other"
                        .into(),
                ));
            }
        }
        Ok(AgentConfig {
            node_name: raw.agent.node_name.unwrap_or_else(|| "unknown".into()),
            listen: raw.agent.listen.unwrap_or_else(|| "127.0.0.1:9464".into()),
            seed: raw.agent.seed.unwrap_or(0),
            flush_interval_ms: raw.agent.flush_interval_ms.unwrap_or(1_000).max(10),
            runtime_shards,
            runtime_batch_size,
            runtime_shard_strategy: raw
                .agent
                .runtime_shard_strategy
                .unwrap_or(RuntimeShardStrategy::Flow),
            cpu_affinity,
            source: raw.agent.source,
            query_files: raw.queries.into_iter().map(|q| q.file).collect(),
            otlp,
            gateway,
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, AgentError> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| AgentError::Config(format!("cannot read {}: {e}", path.display())))?;
        let mut cfg = Self::from_yaml(&yaml)?;
        // Relative paths in the config resolve relative to the config file.
        if let Some(dir) = path.parent() {
            for q in &mut cfg.query_files {
                if q.is_relative() {
                    *q = dir.join(&*q);
                }
            }
            match &mut cfg.source {
                SourceConfig::Pcap { path } => {
                    if path.is_relative() {
                        *path = dir.join(&*path);
                    }
                }
                SourceConfig::Ebpf { object_path, .. } => {
                    if object_path.is_relative() {
                        *object_path = dir.join(&*object_path);
                    }
                }
                SourceConfig::AfPacket { .. } => {}
            }
        }
        Ok(cfg)
    }

    pub fn flush_interval(&self) -> Duration {
        Duration::from_millis(self.flush_interval_ms)
    }

    /// Parse and plan every configured query, failing closed on any error.
    pub fn load_plans(&self) -> Result<Vec<Plan>, AgentError> {
        let hash = HashSpec::new(self.seed);
        let mut plans = Vec::with_capacity(self.query_files.len());
        for file in &self.query_files {
            let yaml = std::fs::read_to_string(file)
                .map_err(|e| AgentError::Config(format!("cannot read {}: {e}", file.display())))?;
            let query = parse_query_yaml(&yaml)
                .map_err(|e| AgentError::Config(format!("{}: {e}", file.display())))?;
            let planned = plan(query, &hash)
                .map_err(|e| AgentError::Config(format!("{}: {e}", file.display())))?;
            plans.push(planned);
        }
        Ok(plans)
    }
}

fn validate_cpu_affinity(
    affinity: Option<&CpuAffinityConfig>,
    runtime_shards: usize,
) -> Result<(), AgentError> {
    let Some(affinity) = affinity else {
        return Ok(());
    };
    if affinity.capture_cpu > MAX_LINUX_CPU_ID {
        return Err(AgentError::Config(format!(
            "agent.cpuAffinity.captureCpu must be between 0 and {MAX_LINUX_CPU_ID}"
        )));
    }
    if affinity.runtime_cpus.len() != runtime_shards {
        return Err(AgentError::Config(format!(
            "agent.cpuAffinity.runtimeCpus must contain exactly one CPU for each of the {runtime_shards} runtime shards"
        )));
    }
    if affinity
        .runtime_cpus
        .iter()
        .any(|&cpu| cpu > MAX_LINUX_CPU_ID)
    {
        return Err(AgentError::Config(format!(
            "agent.cpuAffinity.runtimeCpus values must be between 0 and {MAX_LINUX_CPU_ID}"
        )));
    }
    let unique: std::collections::BTreeSet<_> = affinity.runtime_cpus.iter().copied().collect();
    if unique.len() != affinity.runtime_cpus.len() {
        return Err(AgentError::Config(
            "agent.cpuAffinity.runtimeCpus must not contain duplicate CPUs".into(),
        ));
    }
    Ok(())
}

fn validate_source(source: &SourceConfig) -> Result<(), AgentError> {
    match source {
        SourceConfig::Pcap { .. } => {}
        SourceConfig::AfPacket {
            interface,
            ring_block_size_bytes,
            ring_block_count,
            block_retire_timeout_ms,
        } => {
            validate_interface(interface, "af_packet")?;
            if !(MIN_RING_BLOCK_SIZE_BYTES..=MAX_RING_BLOCK_SIZE_BYTES)
                .contains(ring_block_size_bytes)
                || !ring_block_size_bytes.is_power_of_two()
            {
                return Err(AgentError::Config(format!(
                    "af_packet ringBlockSizeBytes must be a power of two between {MIN_RING_BLOCK_SIZE_BYTES} and {MAX_RING_BLOCK_SIZE_BYTES}"
                )));
            }
            if *ring_block_count == 0 {
                return Err(AgentError::Config(
                    "af_packet ringBlockCount must be positive".into(),
                ));
            }
            let ring_bytes = u64::from(*ring_block_size_bytes) * u64::from(*ring_block_count);
            if ring_bytes > MAX_RING_BYTES {
                return Err(AgentError::Config(format!(
                    "af_packet receive ring is {ring_bytes} bytes; maximum is {MAX_RING_BYTES}"
                )));
            }
            if !(1..=1_000).contains(block_retire_timeout_ms) {
                return Err(AgentError::Config(
                    "af_packet blockRetireTimeoutMs must be between 1 and 1000".into(),
                ));
            }
        }
        SourceConfig::Ebpf {
            interface,
            object_path,
            ring_buffer_bytes,
            ..
        } => {
            validate_interface(interface, "ebpf")?;
            if object_path.as_os_str().is_empty() {
                return Err(AgentError::Config(
                    "ebpf source objectPath must not be empty".into(),
                ));
            }
            if !(MIN_EBPF_RING_BYTES..=MAX_EBPF_RING_BYTES).contains(ring_buffer_bytes)
                || !ring_buffer_bytes.is_power_of_two()
            {
                return Err(AgentError::Config(format!(
                    "ebpf ringBufferBytes must be a power of two between {MIN_EBPF_RING_BYTES} and {MAX_EBPF_RING_BYTES}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_interface(interface: &str, source: &str) -> Result<(), AgentError> {
    if interface.trim().is_empty() {
        return Err(AgentError::Config(format!(
            "{source} source interface must not be empty"
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    agent: RawAgent,
    queries: Vec<RawQueryRef>,
    #[serde(default)]
    export: Option<RawExport>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport {
    #[serde(default)]
    otlp: Option<RawOtlp>,
    #[serde(default)]
    gateway: Option<RawGatewayPush>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOtlp {
    endpoint: String,
    #[serde(default, rename = "intervalMs", alias = "interval_ms")]
    interval_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGatewayPush {
    endpoint: String,
    #[serde(default, rename = "intervalMs", alias = "interval_ms")]
    interval_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    #[serde(default, rename = "nodeName", alias = "node_name")]
    node_name: Option<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    seed: Option<u64>,
    #[serde(default, rename = "flushIntervalMs", alias = "flush_interval_ms")]
    flush_interval_ms: Option<u64>,
    #[serde(default, rename = "runtimeShards", alias = "runtime_shards")]
    runtime_shards: Option<usize>,
    #[serde(default, rename = "runtimeBatchSize", alias = "runtime_batch_size")]
    runtime_batch_size: Option<usize>,
    #[serde(
        default,
        rename = "runtimeShardStrategy",
        alias = "runtime_shard_strategy"
    )]
    runtime_shard_strategy: Option<RuntimeShardStrategy>,
    #[serde(default, rename = "cpuAffinity", alias = "cpu_affinity")]
    cpu_affinity: Option<CpuAffinityConfig>,
    source: SourceConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQueryRef {
    file: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let cfg = AgentConfig::from_yaml(
            r#"
agent:
  nodeName: node-a
  listen: 127.0.0.1:0
  seed: 7
  flushIntervalMs: 250
  runtimeShards: 4
  runtimeBatchSize: 8192
  runtimeShardStrategy: round_robin
  cpuAffinity:
    captureCpu: 0
    runtimeCpus: [1, 2, 3, 4]
  source:
    kind: pcap
    path: demo.pcap
queries:
  - file: q1.yaml
  - file: q2.yaml
"#,
        )
        .unwrap();
        assert_eq!(cfg.node_name, "node-a");
        assert_eq!(cfg.seed, 7);
        assert_eq!(cfg.flush_interval_ms, 250);
        assert_eq!(cfg.runtime_shards, 4);
        assert_eq!(cfg.runtime_batch_size, 8192);
        assert_eq!(cfg.runtime_shard_strategy, RuntimeShardStrategy::RoundRobin);
        assert_eq!(
            cfg.cpu_affinity,
            Some(CpuAffinityConfig {
                capture_cpu: 0,
                runtime_cpus: vec![1, 2, 3, 4],
            })
        );
        assert!(matches!(cfg.source, SourceConfig::Pcap { .. }));
        assert_eq!(cfg.query_files.len(), 2);
    }

    #[test]
    fn af_packet_source_parses() {
        let cfg = AgentConfig::from_yaml(
            "agent:\n  source:\n    kind: af_packet\n    interface: eth0\nqueries:\n  - file: q.yaml\n",
        )
        .unwrap();
        match cfg.source {
            SourceConfig::AfPacket {
                interface,
                ring_block_size_bytes,
                ring_block_count,
                block_retire_timeout_ms,
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(ring_block_size_bytes, 1024 * 1024);
                assert_eq!(ring_block_count, 64);
                assert_eq!(block_retire_timeout_ms, 64);
            }
            other => panic!("wrong source {other:?}"),
        }
        // Defaults applied.
        assert_eq!(cfg.listen, "127.0.0.1:9464");
        assert_eq!(cfg.runtime_shards, 1);
        assert_eq!(cfg.runtime_batch_size, 4096);
        assert_eq!(cfg.runtime_shard_strategy, RuntimeShardStrategy::Flow);
        assert!(cfg.cpu_affinity.is_none());
    }

    #[test]
    fn validates_af_packet_ring_settings() {
        let valid = AgentConfig::from_yaml(
            "agent:\n  source:\n    kind: af_packet\n    interface: eth0\n    ringBlockSizeBytes: 2097152\n    ringBlockCount: 32\n    blockRetireTimeoutMs: 25\nqueries:\n  - file: q.yaml\n",
        )
        .unwrap();
        assert!(matches!(
            valid.source,
            SourceConfig::AfPacket {
                ring_block_size_bytes: 2_097_152,
                ring_block_count: 32,
                block_retire_timeout_ms: 25,
                ..
            }
        ));

        for invalid_source in [
            "interface: ''",
            "interface: eth0\n    ringBlockSizeBytes: 1000000",
            "interface: eth0\n    ringBlockCount: 0",
            "interface: eth0\n    ringBlockSizeBytes: 16777216\n    ringBlockCount: 65",
            "interface: eth0\n    blockRetireTimeoutMs: 0",
        ] {
            let yaml = format!(
                "agent:\n  source:\n    kind: af_packet\n    {invalid_source}\nqueries:\n  - file: q.yaml\n"
            );
            assert!(AgentConfig::from_yaml(&yaml).is_err(), "accepted {yaml}");
        }
    }

    #[test]
    fn parses_and_validates_ebpf_source() {
        let cfg = AgentConfig::from_yaml(
            "agent:\n  source:\n    kind: ebpf\n    interface: eth0\n    objectPath: /usr/lib/flowsketch/flowsketch_tc.bpf.o\n    ringBufferBytes: 8388608\n    fallbackToAfPacket: true\nqueries:\n  - file: q.yaml\n",
        )
        .unwrap();
        assert!(matches!(
            cfg.source,
            SourceConfig::Ebpf {
                ref interface,
                ring_buffer_bytes: 8_388_608,
                fallback_to_af_packet: true,
                ..
            } if interface == "eth0"
        ));

        for invalid_source in [
            "interface: ''\n    objectPath: x.o",
            "interface: eth0\n    objectPath: ''",
            "interface: eth0\n    objectPath: x.o\n    ringBufferBytes: 1000000",
        ] {
            let yaml = format!(
                "agent:\n  source:\n    kind: ebpf\n    {invalid_source}\nqueries:\n  - file: q.yaml\n"
            );
            assert!(AgentConfig::from_yaml(&yaml).is_err(), "accepted {yaml}");
        }
    }

    #[test]
    fn parses_otlp_export_block() {
        let cfg = AgentConfig::from_yaml(
            "agent:\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n\
             export:\n  otlp:\n    endpoint: http://collector:4318\n    intervalMs: 2000\n",
        )
        .unwrap();
        let otlp = cfg.otlp.expect("otlp configured");
        assert_eq!(otlp.endpoint, "http://collector:4318");
        assert_eq!(otlp.interval_ms, 2000);
        assert_eq!(otlp.metrics_url(), "http://collector:4318/v1/metrics");

        // https is rejected with direction (no TLS in v0).
        assert!(AgentConfig::from_yaml(
            "agent:\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n\
             export:\n  otlp:\n    endpoint: https://collector:4318\n",
        )
        .is_err());
    }

    #[test]
    fn parses_gateway_export_block() {
        let cfg = AgentConfig::from_yaml(
            "agent:\n  nodeName: node-a\n  source: {kind: pcap, path: x.pcap}\n\
             queries:\n  - file: q.yaml\n\
             export:\n  gateway:\n    endpoint: http://gw:9465\n    intervalMs: 1000\n",
        )
        .unwrap();
        let gw = cfg.gateway.expect("gateway configured");
        assert_eq!(gw.endpoint, "http://gw:9465");
        assert_eq!(gw.interval_ms, 1000);
        assert_eq!(gw.snapshots_url(), "http://gw:9465/v1/snapshots");

        // https is rejected with direction (no TLS in v0).
        assert!(AgentConfig::from_yaml(
            "agent:\n  nodeName: node-a\n  source: {kind: pcap, path: x.pcap}\n\
             queries:\n  - file: q.yaml\n\
             export:\n  gateway:\n    endpoint: https://gw:9465\n",
        )
        .is_err());
    }

    #[test]
    fn gateway_push_requires_node_name() {
        // The gateway keys snapshots by node name, so gateway mode without
        // an explicit nodeName is rejected rather than defaulting to a
        // shared "unknown" id that would make agents overwrite each other.
        let without_name =
            "agent:\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n\
             export:\n  gateway:\n    endpoint: http://gw:9465\n";
        assert!(AgentConfig::from_yaml(without_name).is_err());

        // A blank/whitespace nodeName is also rejected.
        assert!(AgentConfig::from_yaml(
            "agent:\n  nodeName: '  '\n  source: {kind: pcap, path: x.pcap}\n\
             queries:\n  - file: q.yaml\n\
             export:\n  gateway:\n    endpoint: http://gw:9465\n",
        )
        .is_err());

        // Without gateway push the default nodeName is still fine.
        assert!(AgentConfig::from_yaml(
            "agent:\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n"
        )
        .is_ok());
    }

    #[test]
    fn validates_cpu_affinity_shape_and_bounds() {
        let valid = AgentConfig::from_yaml(
            "agent:\n  runtimeShards: 2\n  cpuAffinity:\n    captureCpu: 0\n    runtimeCpus: [1, 2]\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n",
        )
        .unwrap();
        assert_eq!(valid.cpu_affinity.unwrap().runtime_cpus, vec![1, 2]);

        for affinity in [
            "captureCpu: 0\n    runtimeCpus: [1]",
            "captureCpu: 0\n    runtimeCpus: [1, 1]",
            "captureCpu: 1024\n    runtimeCpus: [1, 2]",
            "captureCpu: 0\n    runtimeCpus: [1, 1024]",
        ] {
            let yaml = format!(
                "agent:\n  runtimeShards: 2\n  cpuAffinity:\n    {affinity}\n  source: {{kind: pcap, path: x.pcap}}\nqueries:\n  - file: q.yaml\n"
            );
            assert!(AgentConfig::from_yaml(&yaml).is_err(), "accepted {yaml}");
        }
    }

    #[test]
    fn rejects_empty_queries_and_unknown_keys() {
        assert!(AgentConfig::from_yaml(
            "agent:\n  source: {kind: pcap, path: x.pcap}\nqueries: []\n"
        )
        .is_err());
        assert!(AgentConfig::from_yaml(
            "agent:\n  source: {kind: pcap, path: x.pcap}\n  bogus: 1\nqueries:\n  - file: q.yaml\n"
        )
        .is_err());
        assert!(AgentConfig::from_yaml(
            "agent:\n  runtimeShards: 0\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n"
        )
        .is_err());
        assert!(AgentConfig::from_yaml(
            "agent:\n  runtimeBatchSize: 65537\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n"
        )
        .is_err());
    }
}
