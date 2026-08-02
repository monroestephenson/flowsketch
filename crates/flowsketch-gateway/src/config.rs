//! Gateway configuration file (YAML).
//!
//! ```yaml
//! gateway:
//!   listen: 0.0.0.0:9465
//!   seed: 0               # must match the agents' seed for mergeability
//!   staleAfterMs: 300000  # forget nodes that stop pushing
//!   maxNodes: 128         # hard admission bound across all queries
//! queries:
//!   - file: examples/queries/top-talkers.yaml
//! ```
//!
//! The gateway loads the same query files as the agents pushing to it:
//! the plan tells it each query's measure semantics, export caps, and
//! expected sketch configuration, so pushed snapshots can be validated
//! instead of trusted.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use flowsketch_core::hash::HashSpec;
use flowsketch_ir::parse_query_yaml;
use flowsketch_planner::{plan, Plan};

use crate::GatewayError;

pub const DEFAULT_MAX_NODES: usize = 128;
pub const MAX_CONFIGURED_NODES: usize = 65_536;

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen: String,
    pub seed: u64,
    pub stale_after_ms: u64,
    pub max_nodes: usize,
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
        Ok(GatewayConfig {
            listen: raw
                .gateway
                .listen
                .unwrap_or_else(|| "127.0.0.1:9465".into()),
            seed: raw.gateway.seed.unwrap_or(0),
            stale_after_ms: raw.gateway.stale_after_ms.unwrap_or(300_000).max(1_000),
            max_nodes,
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
        for file in &self.query_files {
            let yaml = std::fs::read_to_string(file).map_err(|e| {
                GatewayError::Config(format!("cannot read {}: {e}", file.display()))
            })?;
            let query = parse_query_yaml(&yaml)
                .map_err(|e| GatewayError::Config(format!("{}: {e}", file.display())))?;
            let planned = plan(query, &hash)
                .map_err(|e| GatewayError::Config(format!("{}: {e}", file.display())))?;
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
            "gateway:\n  listen: 127.0.0.1:0\n  seed: 7\n  staleAfterMs: 60000\n  maxNodes: 42\n\
             queries:\n  - file: q1.yaml\n  - file: q2.yaml\n",
        )
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:0");
        assert_eq!(cfg.seed, 7);
        assert_eq!(cfg.stale_after_ms, 60_000);
        assert_eq!(cfg.max_nodes, 42);
        assert_eq!(cfg.query_files.len(), 2);
    }

    #[test]
    fn defaults_applied() {
        let cfg = GatewayConfig::from_yaml("gateway: {}\nqueries:\n  - file: q.yaml\n").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:9465");
        assert_eq!(cfg.seed, 0);
        assert_eq!(cfg.stale_after_ms, 300_000);
        assert_eq!(cfg.max_nodes, DEFAULT_MAX_NODES);
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
    }
}
