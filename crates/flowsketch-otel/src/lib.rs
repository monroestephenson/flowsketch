//! OTLP metrics export.
//!
//! Encodes `SketchEstimate`s as OTLP/HTTP + JSON — the protobuf-JSON
//! mapping accepted on `/v1/metrics` by the OpenTelemetry Collector,
//! Grafana Alloy, and the Datadog OTel path — and POSTs them with retry
//! and exponential backoff. No TLS in v0: point it at a local collector
//! sidecar/daemonset, which is the standard deployment shape anyway.

pub mod client;
pub mod encode;

pub use client::{post_metrics, OtlpClientError};
pub use encode::{encode_estimates, EncodeOptions};

/// Exporter configuration (mirrors the agent's `export.otlp` YAML block).
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// Collector base endpoint, e.g. `http://otel-collector:4318`.
    /// `/v1/metrics` is appended automatically if missing.
    pub endpoint: String,
    /// How often the agent exports the latest window.
    pub interval_ms: u64,
}

impl OtlpConfig {
    /// The full metrics URL for this endpoint.
    pub fn metrics_url(&self) -> String {
        let base = self.endpoint.trim_end_matches('/');
        if base.ends_with("/v1/metrics") {
            base.to_string()
        } else {
            format!("{base}/v1/metrics")
        }
    }
}
