//! Gateway configuration file (YAML).
//!
//! ```yaml
//! gateway:
//!   listen: 0.0.0.0:9465
//!   seed: 0               # must match the agents' seed for mergeability
//!   staleAfterMs: 300000  # forget nodes that stop pushing
//!   maxNodes: 128         # hard admission bound across all queries
//!   maxRetainedSketchBytes: 402653184
//! queries:
//!   - file: examples/queries/top-talkers.yaml
//! ```
//!
//! The gateway loads the same query files as the agents pushing to it:
//! the plan tells it each query's measure semantics, export caps, and
//! expected sketch configuration, so pushed snapshots can be validated
//! instead of trusted.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use flowsketch_core::hash::HashSpec;
use flowsketch_ir::parse_query_yaml;
use flowsketch_planner::{plan, Plan};

use crate::GatewayError;

pub const DEFAULT_MAX_NODES: usize = 128;
pub const MAX_CONFIGURED_NODES: usize = 65_536;
pub const DEFAULT_MAX_RETAINED_SKETCH_BYTES: u64 = 384 * 1024 * 1024;
const MIN_MAX_RETAINED_SKETCH_BYTES: u64 = 1024 * 1024;
const MAX_MAX_RETAINED_SKETCH_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen: String,
    pub seed: u64,
    pub stale_after_ms: u64,
    pub max_nodes: usize,
    pub max_retained_sketch_bytes: u64,
    pub query_files: Vec<PathBuf>,
}

impl GatewayConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self, GatewayError> {
        let raw: RawConfig =
            serde_yaml::from_str(yaml).map_err(|e| GatewayError::Config(e.to_string()))?;
        if raw.queries.is_empty() {
            return Err(GatewayError::Config(
                "gateway config must list at least one query file".into(),
            ));
        }
        let max_nodes = raw.gateway.max_nodes.unwrap_or(DEFAULT_MAX_NODES);
        if !(1..=MAX_CONFIGURED_NODES).contains(&max_nodes) {
            return Err(GatewayError::Config(format!(
                "gateway.maxNodes must be between 1 and {MAX_CONFIGURED_NODES}"
            )));
        }
        let max_retained_sketch_bytes = raw
            .gateway
            .max_retained_sketch_bytes
            .unwrap_or(DEFAULT_MAX_RETAINED_SKETCH_BYTES);
        if !(MIN_MAX_RETAINED_SKETCH_BYTES..=MAX_MAX_RETAINED_SKETCH_BYTES)
            .contains(&max_retained_sketch_bytes)
        {
            return Err(GatewayError::Config(format!(
                "gateway.maxRetainedSketchBytes must be between \
                 {MIN_MAX_RETAINED_SKETCH_BYTES} and {MAX_MAX_RETAINED_SKETCH_BYTES}"
            )));
        }
        Ok(GatewayConfig {
            listen: raw
                .gateway
                .listen
                .unwrap_or_else(|| "127.0.0.1:9465".into()),
            seed: raw.gateway.seed.unwrap_or(0),
            stale_after_ms: raw.gateway.stale_after_ms.unwrap_or(300_000).max(1_000),
            max_nodes,
            max_retained_sketch_bytes,
            query_files: raw.queries.into_iter().map(|q| q.file).collect(),
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, GatewayError> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| GatewayError::Config(format!("cannot read {}: {e}", path.display())))?;
        let mut cfg = Self::from_yaml(&yaml)?;
        // Relative paths in the config resolve relative to the config file.
        if let Some(dir) = path.parent() {
            for q in &mut cfg.query_files {
                if q.is_relative() {
                    *q = dir.join(&*q);
                }
            }
        }
        Ok(cfg)
    }

    pub fn stale_after(&self) -> Duration {
        Duration::from_millis(self.stale_after_ms)
    }

    /// Parse and plan every configured query, failing closed on any error.
    pub fn load_plans(&self) -> Result<Vec<Plan>, GatewayError> {
        let hash = HashSpec::new(self.seed);
        let mut plans = Vec::with_capacity(self.query_files.len());
        let mut names = BTreeSet::new();
        for file in &self.query_files {
            let yaml = std::fs::read_to_string(file).map_err(|e| {
                GatewayError::Config(format!("cannot read {}: {e}", file.display()))
            })?;
            let query = parse_query_yaml(&yaml)
                .map_err(|e| GatewayError::Config(format!("{}: {e}", file.display())))?;
            let planned = plan(query, &hash)
                .map_err(|e| GatewayError::Config(format!("{}: {e}", file.display())))?;
            if planned.physical.estimated_state_memory_bytes > self.max_retained_sketch_bytes {
                return Err(GatewayError::Config(format!(
                    "{}: one mergeable state for query {:?} is estimated at {} bytes, \
                     exceeding gateway.maxRetainedSketchBytes={}; no node snapshot could be \
                     admitted",
                    file.display(),
                    planned.query.name,
                    planned.physical.estimated_state_memory_bytes,
                    self.max_retained_sketch_bytes
                )));
            }
            if !names.insert(planned.query.name.clone()) {
                return Err(GatewayError::Config(format!(
                    "duplicate query name {:?}; every configured query name must be unique",
                    planned.query.name
                )));
            }
            plans.push(planned);
        }
        Ok(plans)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    gateway: RawGateway,
    queries: Vec<RawQueryRef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGateway {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    seed: Option<u64>,
    #[serde(default, rename = "staleAfterMs", alias = "stale_after_ms")]
    stale_after_ms: Option<u64>,
    #[serde(default, rename = "maxNodes", alias = "max_nodes")]
    max_nodes: Option<usize>,
    #[serde(
        default,
        rename = "maxRetainedSketchBytes",
        alias = "max_retained_sketch_bytes"
    )]
    max_retained_sketch_bytes: Option<u64>,
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
        let cfg = GatewayConfig::from_yaml(
            "gateway:\n  listen: 127.0.0.1:0\n  seed: 7\n  staleAfterMs: 60000\n  maxNodes: 42\n  maxRetainedSketchBytes: 268435456\n\
             queries:\n  - file: q1.yaml\n  - file: q2.yaml\n",
        )
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:0");
        assert_eq!(cfg.seed, 7);
        assert_eq!(cfg.stale_after_ms, 60_000);
        assert_eq!(cfg.max_nodes, 42);
        assert_eq!(cfg.max_retained_sketch_bytes, 268_435_456);
        assert_eq!(cfg.query_files.len(), 2);
    }

    #[test]
    fn defaults_applied() {
        let cfg = GatewayConfig::from_yaml("gateway: {}\nqueries:\n  - file: q.yaml\n").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:9465");
        assert_eq!(cfg.seed, 0);
        assert_eq!(cfg.stale_after_ms, 300_000);
        assert_eq!(cfg.max_nodes, DEFAULT_MAX_NODES);
        assert_eq!(
            cfg.max_retained_sketch_bytes,
            DEFAULT_MAX_RETAINED_SKETCH_BYTES
        );
    }

    #[test]
    fn rejects_empty_queries_and_unknown_keys() {
        assert!(GatewayConfig::from_yaml("gateway: {}\nqueries: []\n").is_err());
        assert!(
            GatewayConfig::from_yaml("gateway:\n  bogus: 1\nqueries:\n  - file: q.yaml\n").is_err()
        );
        assert!(
            GatewayConfig::from_yaml("gateway:\n  maxNodes: 0\nqueries:\n  - file: q.yaml\n")
                .is_err()
        );
        for bytes in [
            MIN_MAX_RETAINED_SKETCH_BYTES - 1,
            MAX_MAX_RETAINED_SKETCH_BYTES + 1,
        ] {
            let yaml = format!(
                "gateway:\n  maxRetainedSketchBytes: {bytes}\nqueries:\n  - file: q.yaml\n"
            );
            assert!(GatewayConfig::from_yaml(&yaml).is_err(), "accepted {bytes}");
        }
    }

    #[test]
    fn load_plans_rejects_duplicate_query_names() {
        let dir = std::env::temp_dir().join(format!(
            "flowsketch-gateway-duplicate-plan-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let query = dir.join("query.yaml");
        std::fs::write(
            &query,
            "name: duplicate\nwindow: {size: 10s}\nmeasure: {type: count}\n",
        )
        .unwrap();
        let config = GatewayConfig::from_yaml(&format!(
            "gateway: {{}}\nqueries:\n  - file: '{}'\n  - file: '{}'\n",
            query.display(),
            query.display()
        ))
        .unwrap();
        let error = config.load_plans().unwrap_err().to_string();
        assert!(error.contains("duplicate query name"), "{error}");

        let scanner = dir.join("scanner.yaml");
        std::fs::write(
            &scanner,
            "name: scanner\nwindow: {size: 60s, slide: 10s}\ngroupBy: [src.ip]\n\
             measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.02}}\n\
             export: {maxSeries: 500}\nresources: {maxMemory: 64MiB}\n",
        )
        .unwrap();
        let too_small = GatewayConfig::from_yaml(&format!(
            "gateway:\n  maxRetainedSketchBytes: 1048576\nqueries:\n  - file: '{}'\n",
            scanner.display()
        ))
        .unwrap();
        let error = too_small.load_plans().unwrap_err().to_string();
        assert!(
            error.contains("no node snapshot could be admitted"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
