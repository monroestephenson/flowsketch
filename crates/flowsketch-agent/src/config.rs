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
//!   maxSketchMemoryBytes: 1073741824
//!   cpuAffinity:              # optional, Linux only
//!     captureCpus: [0]
//!     runtimeCpus: [1, 2, 3, 4]
//!   source:
//!     kind: pcap            # pcap | af_packet | ebpf
//!     path: demo.pcap       # pcap: file to replay
//!     interface: eth0       # af_packet: interface to sniff
//!     ringBlockSizeBytes: 1048576
//!     ringBlockCount: 64
//!     blockRetireTimeoutMs: 64
//!     fanoutMode: rx_queue # single | hash | rx_queue
//!     fanoutGroup: 0       # ask Linux for a unique group in this netns
//! queries:
//!   - file: examples/queries/top-talkers.yaml
//! ```

use std::collections::BTreeSet;
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

/// Linux AF_PACKET socket fan-out policy. `rx_queue` maps the kernel skb
/// queue_mapping to a capture lane; `hash` uses the kernel flow hash and is
/// useful on virtual/single-queue devices.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AfPacketFanoutMode {
    Single,
    Hash,
    RxQueue,
}

const fn default_af_packet_fanout_mode() -> AfPacketFanoutMode {
    AfPacketFanoutMode::Single
}

/// Optional Linux CPU placement for the capture thread and each long-lived
/// runtime worker. CPU identifiers are Linux logical CPU numbers.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CpuAffinityConfig {
    #[serde(
        rename = "captureCpus",
        alias = "capture_cpus",
        alias = "captureCpu",
        alias = "capture_cpu",
        deserialize_with = "deserialize_capture_cpus"
    )]
    pub capture_cpus: Vec<usize>,
    #[serde(rename = "runtimeCpus", alias = "runtime_cpus")]
    pub runtime_cpus: Vec<usize>,
}

fn deserialize_capture_cpus<'de, D>(deserializer: D) -> Result<Vec<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(usize),
        Many(Vec<usize>),
    }

    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(cpu) => vec![cpu],
        OneOrMany::Many(cpus) => cpus,
    })
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
        /// Kernel packet-socket fan-out. Non-single modes create one socket
        /// and capture lane per runtime shard.
        #[serde(
            default = "default_af_packet_fanout_mode",
            rename = "fanoutMode",
            alias = "fanout_mode"
        )]
        fanout_mode: AfPacketFanoutMode,
        /// 16-bit packet-socket fan-out group. Zero derives a process-local
        /// group at startup. An explicit value must be unique to this agent on
        /// the interface so another capture process cannot join its group.
        #[serde(default, rename = "fanoutGroup", alias = "fanout_group")]
        fanout_group: u16,
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

impl SourceConfig {
    pub(crate) fn capture_lane_count(&self, runtime_shards: usize) -> usize {
        match self {
            Self::AfPacket { fanout_mode, .. } if *fanout_mode != AfPacketFanoutMode::Single => {
                runtime_shards
            }
            _ => 1,
        }
    }

    pub(crate) fn af_packet_fanout_lanes(&self, runtime_shards: usize) -> usize {
        match self {
            Self::AfPacket { fanout_mode, .. } if *fanout_mode != AfPacketFanoutMode::Single => {
                runtime_shards
            }
            _ => 0,
        }
    }
}

const MIN_RING_BLOCK_SIZE_BYTES: u32 = 64 * 1024;
const MAX_RING_BLOCK_SIZE_BYTES: u32 = 16 * 1024 * 1024;
const MAX_RING_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_EBPF_RING_BYTES: u32 = 64 * 1024;
const MAX_EBPF_RING_BYTES: u32 = 1024 * 1024 * 1024;
const MAX_LINUX_CPU_ID: usize = 1023;
const MAX_LINUX_INTERFACE_NAME_BYTES: usize = 15;
pub const DEFAULT_MAX_SKETCH_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_MAX_SKETCH_MEMORY_BYTES: u64 = 1024 * 1024;
const MAX_MAX_SKETCH_MEMORY_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

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
    /// Hard preflight ceiling for the aggregate planner estimate across all
    /// queries and runtime shards. Capture rings and event channels are
    /// configured and bounded separately.
    pub max_sketch_memory_bytes: u64,
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
        if let Some(node_name) = raw.agent.node_name.as_deref() {
            if node_name.trim().is_empty() {
                return Err(AgentError::Config(
                    "agent.nodeName must not be blank".into(),
                ));
            }
            if node_name.len() > flowsketch_gateway::batch::MAX_NODE_NAME_BYTES {
                return Err(AgentError::Config(format!(
                    "agent.nodeName is {} bytes; maximum is {}",
                    node_name.len(),
                    flowsketch_gateway::batch::MAX_NODE_NAME_BYTES
                )));
            }
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
        let max_sketch_memory_bytes = raw
            .agent
            .max_sketch_memory_bytes
            .unwrap_or(DEFAULT_MAX_SKETCH_MEMORY_BYTES);
        if !(MIN_MAX_SKETCH_MEMORY_BYTES..=MAX_MAX_SKETCH_MEMORY_BYTES)
            .contains(&max_sketch_memory_bytes)
        {
            return Err(AgentError::Config(format!(
                "agent.maxSketchMemoryBytes must be between {MIN_MAX_SKETCH_MEMORY_BYTES} and \
                 {MAX_MAX_SKETCH_MEMORY_BYTES}"
            )));
        }
        let runtime_shard_strategy = raw
            .agent
            .runtime_shard_strategy
            .unwrap_or(RuntimeShardStrategy::Flow);
        let cpu_affinity = raw.agent.cpu_affinity.clone();
        validate_source(&raw.agent.source, runtime_shards, runtime_shard_strategy)?;
        validate_cpu_affinity(
            cpu_affinity.as_ref(),
            raw.agent.source.capture_lane_count(runtime_shards),
            runtime_shards,
        )?;
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
            if raw.agent.node_name.is_none() {
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
            max_sketch_memory_bytes,
            runtime_shard_strategy,
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
        let mut names = BTreeSet::new();
        for file in &self.query_files {
            let yaml = std::fs::read_to_string(file)
                .map_err(|e| AgentError::Config(format!("cannot read {}: {e}", file.display())))?;
            let query = parse_query_yaml(&yaml)
                .map_err(|e| AgentError::Config(format!("{}: {e}", file.display())))?;
            let planned = plan(query, &hash)
                .map_err(|e| AgentError::Config(format!("{}: {e}", file.display())))?;
            if !names.insert(planned.query.name.clone()) {
                return Err(AgentError::Config(format!(
                    "duplicate query name {:?}; every configured query name must be unique",
                    planned.query.name
                )));
            }
            plans.push(planned);
        }
        let per_shard_bytes = plans.iter().try_fold(0u64, |total, planned| {
            total.checked_add(planned.physical.estimated_memory_bytes)
        });
        let aggregate_bytes = per_shard_bytes
            .and_then(|bytes| bytes.checked_mul(self.runtime_shards as u64))
            .ok_or_else(|| {
                AgentError::Config(
                    "aggregate planned sketch memory overflows the supported byte range".into(),
                )
            })?;
        if aggregate_bytes > self.max_sketch_memory_bytes {
            return Err(AgentError::Config(format!(
                "aggregate planned sketch memory is {aggregate_bytes} bytes across {} runtime \
                 shard(s), exceeding agent.maxSketchMemoryBytes={}; reduce queries or shards, \
                 loosen query accuracy, or raise the process budget",
                self.runtime_shards, self.max_sketch_memory_bytes
            )));
        }
        Ok(plans)
    }
}

fn validate_cpu_affinity(
    affinity: Option<&CpuAffinityConfig>,
    capture_lanes: usize,
    runtime_shards: usize,
) -> Result<(), AgentError> {
    let Some(affinity) = affinity else {
        return Ok(());
    };
    if affinity.capture_cpus.len() != capture_lanes {
        return Err(AgentError::Config(format!(
            "agent.cpuAffinity.captureCpus must contain exactly one CPU for each of the {capture_lanes} capture lanes"
        )));
    }
    if affinity
        .capture_cpus
        .iter()
        .any(|&cpu| cpu > MAX_LINUX_CPU_ID)
    {
        return Err(AgentError::Config(format!(
            "agent.cpuAffinity.captureCpus values must be between 0 and {MAX_LINUX_CPU_ID}"
        )));
    }
    let unique_capture: std::collections::BTreeSet<_> =
        affinity.capture_cpus.iter().copied().collect();
    if unique_capture.len() != affinity.capture_cpus.len() {
        return Err(AgentError::Config(
            "agent.cpuAffinity.captureCpus must not contain duplicate CPUs".into(),
        ));
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

fn validate_source(
    source: &SourceConfig,
    runtime_shards: usize,
    shard_strategy: RuntimeShardStrategy,
) -> Result<(), AgentError> {
    match source {
        SourceConfig::Pcap { .. } => {}
        SourceConfig::AfPacket {
            interface,
            ring_block_size_bytes,
            ring_block_count,
            block_retire_timeout_ms,
            fanout_mode,
            ..
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
            let lanes = if *fanout_mode == AfPacketFanoutMode::Single {
                1
            } else {
                runtime_shards
            };
            let aggregate_ring_bytes = ring_bytes
                .checked_mul(lanes as u64)
                .ok_or_else(|| AgentError::Config("AF_PACKET ring size overflows u64".into()))?;
            if aggregate_ring_bytes > MAX_RING_BYTES {
                return Err(AgentError::Config(format!(
                    "aggregate AF_PACKET receive rings are {aggregate_ring_bytes} bytes across {lanes} lane(s); maximum is {MAX_RING_BYTES}"
                )));
            }
            if !(1..=1_000).contains(block_retire_timeout_ms) {
                return Err(AgentError::Config(
                    "af_packet blockRetireTimeoutMs must be between 1 and 1000".into(),
                ));
            }
            if *fanout_mode != AfPacketFanoutMode::Single {
                if runtime_shards < 2 {
                    return Err(AgentError::Config(
                        "af_packet fanoutMode requires at least two runtimeShards".into(),
                    ));
                }
                if shard_strategy != RuntimeShardStrategy::Flow {
                    return Err(AgentError::Config(
                        "af_packet fanoutMode requires runtimeShardStrategy: flow because the kernel-selected lane maps directly to a runtime shard"
                            .into(),
                    ));
                }
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
    if interface.len() > MAX_LINUX_INTERFACE_NAME_BYTES
        || interface.contains('/')
        || interface.contains('\0')
    {
        return Err(AgentError::Config(format!(
            "{source} source interface must be a Linux interface name of at most \
             {MAX_LINUX_INTERFACE_NAME_BYTES} bytes without '/' or NUL"
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
        rename = "maxSketchMemoryBytes",
        alias = "max_sketch_memory_bytes"
    )]
    max_sketch_memory_bytes: Option<u64>,
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
  maxSketchMemoryBytes: 2147483648
  runtimeShardStrategy: round_robin
  cpuAffinity:
    captureCpus: [0]
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
        assert_eq!(cfg.max_sketch_memory_bytes, 2_147_483_648);
        assert_eq!(cfg.runtime_shard_strategy, RuntimeShardStrategy::RoundRobin);
        assert_eq!(
            cfg.cpu_affinity,
            Some(CpuAffinityConfig {
                capture_cpus: vec![0],
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
                fanout_mode,
                fanout_group,
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(ring_block_size_bytes, 1024 * 1024);
                assert_eq!(ring_block_count, 64);
                assert_eq!(block_retire_timeout_ms, 64);
                assert_eq!(fanout_mode, AfPacketFanoutMode::Single);
                assert_eq!(fanout_group, 0);
            }
            other => panic!("wrong source {other:?}"),
        }
        // Defaults applied.
        assert_eq!(cfg.listen, "127.0.0.1:9464");
        assert_eq!(cfg.runtime_shards, 1);
        assert_eq!(cfg.runtime_batch_size, 4096);
        assert_eq!(cfg.max_sketch_memory_bytes, DEFAULT_MAX_SKETCH_MEMORY_BYTES);
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
            "interface: ../eth0",
            "interface: interface-name-too-long",
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
    fn validates_af_packet_fanout_against_runtime_shape() {
        let valid = AgentConfig::from_yaml(
            "agent:\n  runtimeShards: 4\n  runtimeShardStrategy: flow\n  source:\n    kind: af_packet\n    interface: eth0\n    ringBlockCount: 16\n    fanoutMode: rx_queue\n    fanoutGroup: 77\nqueries:\n  - file: q.yaml\n",
        )
        .unwrap();
        assert_eq!(valid.source.capture_lane_count(valid.runtime_shards), 4);
        assert!(matches!(
            valid.source,
            SourceConfig::AfPacket {
                fanout_mode: AfPacketFanoutMode::RxQueue,
                fanout_group: 77,
                ..
            }
        ));

        for agent in [
            "runtimeShards: 1\n  source: {kind: af_packet, interface: eth0, fanoutMode: hash}",
            "runtimeShards: 2\n  runtimeShardStrategy: round_robin\n  source: {kind: af_packet, interface: eth0, fanoutMode: rx_queue}",
            "runtimeShards: 2\n  source: {kind: af_packet, interface: eth0, ringBlockSizeBytes: 16777216, ringBlockCount: 33, fanoutMode: hash}",
        ] {
            let yaml = format!("agent:\n  {agent}\nqueries:\n  - file: q.yaml\n");
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

        let oversized = "n".repeat(flowsketch_gateway::batch::MAX_NODE_NAME_BYTES + 1);
        let yaml = format!(
            "agent:\n  nodeName: {oversized}\n  source: {{kind: pcap, path: x.pcap}}\n\
             queries:\n  - file: q.yaml\n"
        );
        assert!(AgentConfig::from_yaml(&yaml).is_err());
    }

    #[test]
    fn validates_cpu_affinity_shape_and_bounds() {
        let valid = AgentConfig::from_yaml(
            "agent:\n  runtimeShards: 2\n  cpuAffinity:\n    captureCpus: [0]\n    runtimeCpus: [1, 2]\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n",
        )
        .unwrap();
        assert_eq!(valid.cpu_affinity.unwrap().runtime_cpus, vec![1, 2]);

        let legacy = AgentConfig::from_yaml(
            "agent:\n  runtimeShards: 2\n  cpuAffinity:\n    captureCpu: 0\n    runtimeCpus: [1, 2]\n  source: {kind: pcap, path: x.pcap}\nqueries:\n  - file: q.yaml\n",
        )
        .unwrap();
        assert_eq!(legacy.cpu_affinity.unwrap().capture_cpus, vec![0]);

        for affinity in [
            "captureCpus: []\n    runtimeCpus: [1, 2]",
            "captureCpus: [0]\n    runtimeCpus: [1]",
            "captureCpus: [0]\n    runtimeCpus: [1, 1]",
            "captureCpus: [1024]\n    runtimeCpus: [1, 2]",
            "captureCpus: [0]\n    runtimeCpus: [1, 1024]",
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
        for bytes in [
            MIN_MAX_SKETCH_MEMORY_BYTES - 1,
            MAX_MAX_SKETCH_MEMORY_BYTES + 1,
        ] {
            let yaml = format!(
                "agent:\n  maxSketchMemoryBytes: {bytes}\n  source: {{kind: pcap, path: x.pcap}}\nqueries:\n  - file: q.yaml\n"
            );
            assert!(AgentConfig::from_yaml(&yaml).is_err(), "accepted {bytes}");
        }
    }

    #[test]
    fn load_plans_rejects_duplicate_names_and_aggregate_memory_over_budget() {
        let dir = std::env::temp_dir().join(format!(
            "flowsketch-agent-plan-budget-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let query = dir.join("query.yaml");
        std::fs::write(
            &query,
            "name: bounded\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: heavy_hitters, value: bytes, limit: 100}\n\
             resources: {maxMemory: 64MiB}\n",
        )
        .unwrap();

        let duplicate = AgentConfig::from_yaml(&format!(
            "agent:\n  source: {{kind: pcap, path: x.pcap}}\nqueries:\n  - file: '{}'\n  - file: '{}'\n",
            query.display(),
            query.display()
        ))
        .unwrap();
        let error = duplicate.load_plans().unwrap_err().to_string();
        assert!(error.contains("duplicate query name"), "{error}");

        let over_budget = AgentConfig::from_yaml(&format!(
            "agent:\n  runtimeShards: 2\n  maxSketchMemoryBytes: 1048576\n  source: {{kind: pcap, path: x.pcap}}\nqueries:\n  - file: '{}'\n",
            query.display()
        ))
        .unwrap();
        let error = over_budget.load_plans().unwrap_err().to_string();
        assert!(error.contains("aggregate planned sketch memory"), "{error}");

        std::fs::remove_dir_all(dir).unwrap();
    }
}
