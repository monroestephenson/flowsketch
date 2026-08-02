//! `SketchEstimate` -> OTLP JSON (the protobuf-JSON mapping of
//! `ExportMetricsServiceRequest`).
//!
//! The export naming contract uses
//! `network.flowsketch.<unit>.estimated` gauges plus separate
//! `.lower_bound`, `.upper_bound`, and `.confidence` gauges when available;
//! resource attributes carry
//! `service.name`/`host.name`, and metric attributes carry the query
//! metadata (`flowsketch.query.name`, `flowsketch.algorithm`,
//! `flowsketch.window`, `flowsketch.error.kind`) plus group labels mapped
//! to OTel network conventions where one exists (`src.ip` ->
//! `source.address`, `dst.port` -> `destination.port`,
//! `protocol` -> `network.protocol.name`, ...).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use flowsketch_core::SketchEstimate;

/// Per-query metadata the encoder needs beyond the estimate itself.
#[derive(Debug, Clone)]
pub struct QueryMeta {
    /// Which `network.flowsketch.<unit>.estimated` metric this query feeds
    /// (e.g. "bytes", "packets", "distinct", "entropy", "quantile",
    /// "count").
    pub unit: String,
    pub window: String,
    pub error_kind: String,
}

#[derive(Debug, Clone)]
pub struct EncodeOptions {
    /// `service.name` resource attribute.
    pub service_name: String,
    /// `host.name` resource attribute (the agent's node name).
    pub host_name: String,
    /// Per-query metadata keyed by query name; queries without an entry
    /// fall back to unit "value".
    pub queries: BTreeMap<String, QueryMeta>,
}

/// Map a FlowSketch group field to its OTel attribute name.
fn otel_attribute_name(field: &str) -> String {
    match field {
        "src.ip" => "source.address".to_string(),
        "dst.ip" => "destination.address".to_string(),
        "src.port" => "source.port".to_string(),
        "dst.port" => "destination.port".to_string(),
        "protocol" => "network.protocol.name".to_string(),
        other => format!("flowsketch.group.{}", other.replace('.', "_")),
    }
}

fn kv(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

/// Encode estimates into one `ExportMetricsServiceRequest` JSON document.
/// Estimates are grouped into one metric per unit; each estimate becomes a
/// gauge data point timestamped at its window end. Returns `None` when
/// there is nothing to export.
pub fn encode_estimates(estimates: &[SketchEstimate], opts: &EncodeOptions) -> Option<Value> {
    if estimates.is_empty() {
        return None;
    }

    // Full metric name -> (description, data points).
    let mut by_metric: BTreeMap<String, (&'static str, Vec<Value>)> = BTreeMap::new();
    for e in estimates {
        let meta = opts.queries.get(&e.query_name);
        let unit = meta
            .map(|m| m.unit.clone())
            .unwrap_or_else(|| "value".to_string());

        let mut attributes = vec![
            kv("flowsketch.query.name", &e.query_name),
            kv("flowsketch.algorithm", &e.algorithm),
        ];
        if let Some(m) = meta {
            attributes.push(kv("flowsketch.window", &m.window));
            attributes.push(kv("flowsketch.error.kind", &m.error_kind));
        }
        for (field, value) in &e.group {
            attributes.push(kv(&otel_attribute_name(field), value));
        }

        // u64 nanos exceed JSON safe integers; the OTLP JSON mapping
        // represents 64-bit ints as strings.
        let point = |value: f64| {
            json!({
                "timeUnixNano": e.window_end_nanos.to_string(),
                "startTimeUnixNano": e.window_start_nanos.to_string(),
                "asDouble": value,
                "attributes": attributes.clone(),
            })
        };
        let base_name = format!("network.flowsketch.{unit}.estimated");
        by_metric
            .entry(base_name.clone())
            .or_insert_with(|| {
                (
                    "Approximate telemetry estimate from a bounded-memory sketch.",
                    Vec::new(),
                )
            })
            .1
            .push(point(e.estimate));

        // OTLP gauge attributes define series identity. Numeric bounds must
        // therefore be data-point values in stable companion metrics, never
        // continuously varying string attributes on the estimate series.
        for (suffix, description, value) in [
            (
                "lower_bound",
                "Lower error bound for the corresponding FlowSketch estimate.",
                e.lower_bound,
            ),
            (
                "upper_bound",
                "Upper error bound for the corresponding FlowSketch estimate.",
                e.upper_bound,
            ),
            (
                "confidence",
                "Confidence level for the corresponding FlowSketch error interval.",
                e.confidence,
            ),
        ] {
            if let Some(value) = value {
                by_metric
                    .entry(format!("{base_name}.{suffix}"))
                    .or_insert_with(|| (description, Vec::new()))
                    .1
                    .push(point(value));
            }
        }
    }

    let metrics: Vec<Value> = by_metric
        .into_iter()
        .map(|(name, (description, data_points))| {
            json!({
                "name": name,
                "description": description,
                "gauge": { "dataPoints": data_points },
            })
        })
        .collect();

    Some(json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [
                    kv("service.name", &opts.service_name),
                    kv("host.name", &opts.host_name),
                ]
            },
            "scopeMetrics": [{
                "scope": { "name": "flowsketch", "version": env!("CARGO_PKG_VERSION") },
                "metrics": metrics,
            }]
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate(query: &str, group: Vec<(&str, &str)>, value: f64) -> SketchEstimate {
        SketchEstimate {
            query_name: query.to_string(),
            window_start_nanos: 1_000,
            window_end_nanos: 61_000,
            group: group
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            estimate: value,
            lower_bound: Some(value - 1.0),
            upper_bound: Some(value + 1.0),
            confidence: Some(0.95),
            algorithm: "spacesaving".to_string(),
            sketch_bytes: 100,
            update_count: 10,
        }
    }

    fn options() -> EncodeOptions {
        let mut queries = BTreeMap::new();
        queries.insert(
            "top_talkers".to_string(),
            QueryMeta {
                unit: "bytes".to_string(),
                window: "60s".to_string(),
                error_kind: "candidate-upper-bound".to_string(),
            },
        );
        EncodeOptions {
            service_name: "flowsketch-agent".to_string(),
            host_name: "node-a".to_string(),
            queries,
        }
    }

    #[test]
    fn encodes_gauge_with_conventions() {
        let es = vec![estimate(
            "top_talkers",
            vec![
                ("src.ip", "10.0.0.1"),
                ("dst.port", "443"),
                ("protocol", "tcp"),
            ],
            1234.0,
        )];
        let doc = encode_estimates(&es, &options()).unwrap();

        let metrics = doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        let metric = metrics
            .iter()
            .find(|metric| metric["name"] == "network.flowsketch.bytes.estimated")
            .unwrap();
        assert_eq!(metric["name"], "network.flowsketch.bytes.estimated");
        let point = &metric["gauge"]["dataPoints"][0];
        assert_eq!(point["asDouble"], 1234.0);
        assert_eq!(point["timeUnixNano"], "61000");

        let attrs: BTreeMap<String, String> = point["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["key"].as_str().unwrap().to_string(),
                    a["value"]["stringValue"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(attrs["flowsketch.query.name"], "top_talkers");
        assert_eq!(attrs["flowsketch.algorithm"], "spacesaving");
        assert_eq!(attrs["flowsketch.window"], "60s");
        assert_eq!(attrs["flowsketch.error.kind"], "candidate-upper-bound");
        assert_eq!(attrs["source.address"], "10.0.0.1");
        assert_eq!(attrs["destination.port"], "443");
        assert_eq!(attrs["network.protocol.name"], "tcp");
        assert!(!attrs.contains_key("flowsketch.bound.lower"));
        assert!(!attrs.contains_key("flowsketch.bound.upper"));

        let companion_value = |suffix: &str| {
            metrics
                .iter()
                .find(|metric| {
                    metric["name"] == format!("network.flowsketch.bytes.estimated.{suffix}")
                })
                .unwrap()["gauge"]["dataPoints"][0]["asDouble"]
                .as_f64()
                .unwrap()
        };
        assert_eq!(companion_value("lower_bound"), 1233.0);
        assert_eq!(companion_value("upper_bound"), 1235.0);
        assert_eq!(companion_value("confidence"), 0.95);

        let resource = &doc["resourceMetrics"][0]["resource"]["attributes"];
        assert!(
            resource
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["key"] == "service.name"
                    && a["value"]["stringValue"] == "flowsketch-agent")
        );
    }

    #[test]
    fn groups_multiple_units_into_separate_metrics() {
        let mut opts = options();
        opts.queries.insert(
            "scanners".to_string(),
            QueryMeta {
                unit: "distinct".to_string(),
                window: "60s".to_string(),
                error_kind: "relative".to_string(),
            },
        );
        let es = vec![
            estimate("top_talkers", vec![("src.ip", "10.0.0.1")], 100.0),
            estimate("scanners", vec![("src.ip", "10.0.0.2")], 5000.0),
        ];
        let doc = encode_estimates(&es, &opts).unwrap();
        let metrics = doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = metrics
            .iter()
            .map(|m| m["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"network.flowsketch.bytes.estimated"));
        assert!(names.contains(&"network.flowsketch.distinct.estimated"));
    }

    #[test]
    fn empty_input_encodes_nothing() {
        assert!(encode_estimates(&[], &options()).is_none());
    }
}
