//! Agent configuration file (YAML).
//!
//! ```yaml
//! agent:
//!   nodeName: node-a
//!   listen: 127.0.0.1:9464
//!   seed: 0
//!   flushIntervalMs: 1000
//!   source:
//!     kind: pcap            # pcap | af_packet
//!     path: demo.pcap       # pcap: file to replay
//!     interface: eth0       # af_packet: interface to sniff
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

/// Where packets come from.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConfig {
    /// Replay a pcap file, then keep serving results (demo/test mode).
    Pcap { path: PathBuf },
    /// Live capture from a network interface via an AF_PACKET raw socket
    /// (Linux; requires CAP_NET_RAW).
    AfPacket { interface: String },
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub node_name: String,
    pub listen: String,
    pub seed: u64,
    pub flush_interval_ms: u64,
    pub source: SourceConfig,
    pub query_files: Vec<PathBuf>,
    /// OTLP export, if configured.
    pub otlp: Option<flowsketch_otel::OtlpConfig>,
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
        let otlp = raw.export.and_then(|e| e.otlp).map(|o| {
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
        Ok(AgentConfig {
            node_name: raw.agent.node_name.unwrap_or_else(|| "unknown".into()),
            listen: raw.agent.listen.unwrap_or_else(|| "127.0.0.1:9464".into()),
            seed: raw.agent.seed.unwrap_or(0),
            flush_interval_ms: raw.agent.flush_interval_ms.unwrap_or(1_000).max(10),
            source: raw.agent.source,
            query_files: raw.queries.into_iter().map(|q| q.file).collect(),
            otlp,
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
            if let SourceConfig::Pcap { path: p } = &mut cfg.source {
                if p.is_relative() {
                    *p = dir.join(&*p);
                }
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    agent: RawAgent,
    queries: Vec<RawQueryRef>,
    #[serde(default)]
    export: Option<RawExport>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport {
    #[serde(default)]
    otlp: Option<RawOtlp>,
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
struct RawAgent {
    #[serde(default, rename = "nodeName", alias = "node_name")]
    node_name: Option<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    seed: Option<u64>,
    #[serde(default, rename = "flushIntervalMs", alias = "flush_interval_ms")]
    flush_interval_ms: Option<u64>,
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
            SourceConfig::AfPacket { interface } => assert_eq!(interface, "eth0"),
            other => panic!("wrong source {other:?}"),
        }
        // Defaults applied.
        assert_eq!(cfg.listen, "127.0.0.1:9464");
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
    fn rejects_empty_queries_and_unknown_keys() {
        assert!(AgentConfig::from_yaml(
            "agent:\n  source: {kind: pcap, path: x.pcap}\nqueries: []\n"
        )
        .is_err());
        assert!(AgentConfig::from_yaml(
            "agent:\n  source: {kind: pcap, path: x.pcap}\n  bogus: 1\nqueries:\n  - file: q.yaml\n"
        )
        .is_err());
    }
}
