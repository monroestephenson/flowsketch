//! Prometheus text exposition (version 0.0.4) for sketch estimates.
//!
//! Every sample carries `algorithm`, `window`, and `error_kind` labels so
//! the approximation is explicit, and every query's series count is hard-
//! capped: an approximate high-cardinality telemetry tool must not create a
//! high-cardinality metrics disaster.

use std::collections::BTreeMap;

use flowsketch_core::SketchEstimate;
use flowsketch_ir::logical::humanize_nanos;

/// Per-query rendering settings.
#[derive(Debug, Clone)]
pub struct QueryExportInfo {
    /// `error_kind` label value (from the planner's error contract).
    pub error_kind: String,
    /// Hard cap on exported series for this query.
    pub max_series: usize,
    /// Window size in nanos (rendered as the `window` label).
    pub window_size_nanos: u64,
}

/// Render estimates as Prometheus text exposition.
///
/// Estimates are grouped by query; within a query, the highest estimates
/// win the series budget. Returns the exposition body plus per-query
/// counts of series dropped by the cap.
pub fn render(
    estimates: &[SketchEstimate],
    info: &BTreeMap<String, QueryExportInfo>,
) -> (String, BTreeMap<String, usize>) {
    let mut by_query: BTreeMap<&str, Vec<&SketchEstimate>> = BTreeMap::new();
    for e in estimates {
        by_query.entry(e.query_name.as_str()).or_default().push(e);
    }

    let mut out = String::new();
    let mut dropped: BTreeMap<String, usize> = BTreeMap::new();

    out.push_str("# HELP flowsketch_estimate Approximate query result from a bounded-memory sketch.\n");
    out.push_str("# TYPE flowsketch_estimate gauge\n");

    for (query, mut es) in by_query {
        let default_info = QueryExportInfo {
            error_kind: "unknown".to_string(),
            max_series: 1000,
            window_size_nanos: 0,
        };
        let qi = info.get(query).unwrap_or(&default_info);

        es.sort_by(|a, b| {
            b.estimate
                .partial_cmp(&a.estimate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if es.len() > qi.max_series {
            dropped.insert(query.to_string(), es.len() - qi.max_series);
            es.truncate(qi.max_series);
        }

        for e in es {
            let mut labels: Vec<(String, String)> = vec![
                ("query".to_string(), e.query_name.clone()),
                ("algorithm".to_string(), e.algorithm.clone()),
                ("error_kind".to_string(), qi.error_kind.clone()),
            ];
            if qi.window_size_nanos > 0 {
                labels.push((
                    "window".to_string(),
                    humanize_nanos(qi.window_size_nanos),
                ));
            }
            for (name, value) in &e.group {
                labels.push((sanitize_label_name(name), value.clone()));
            }
            out.push_str("flowsketch_estimate{");
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(k);
                out.push_str("=\"");
                out.push_str(&escape_label_value(v));
                out.push('"');
            }
            out.push_str("} ");
            out.push_str(&format_value(e.estimate));
            out.push('\n');
        }
    }

    // Health metrics: make the guardrail itself observable.
    out.push_str(
        "# HELP flowsketch_export_series_dropped_total Series dropped by the per-query export cap.\n",
    );
    out.push_str("# TYPE flowsketch_export_series_dropped_total counter\n");
    for (query, n) in &dropped {
        out.push_str(&format!(
            "flowsketch_export_series_dropped_total{{query=\"{}\"}} {}\n",
            escape_label_value(query),
            n
        ));
    }

    (out, dropped)
}

/// `src.ip` -> `src_ip`; anything not `[a-zA-Z0-9_]` becomes `_`.
pub fn sanitize_label_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    s
}

/// Escape backslash, double-quote, and newline per the exposition format.
pub fn escape_label_value(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn format_value(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate(query: &str, src: &str, value: f64) -> SketchEstimate {
        SketchEstimate {
            query_name: query.to_string(),
            window_start_nanos: 0,
            window_end_nanos: 60_000_000_000,
            group: vec![("src.ip".to_string(), src.to_string())],
            estimate: value,
            lower_bound: None,
            upper_bound: None,
            confidence: None,
            algorithm: "spacesaving".to_string(),
            sketch_bytes: 1024,
            update_count: 10,
        }
    }

    fn info(max_series: usize) -> BTreeMap<String, QueryExportInfo> {
        let mut m = BTreeMap::new();
        m.insert(
            "q".to_string(),
            QueryExportInfo {
                error_kind: "candidate-upper-bound".to_string(),
                max_series,
                window_size_nanos: 60_000_000_000,
            },
        );
        m
    }

    #[test]
    fn renders_labeled_gauges() {
        let (text, dropped) = render(&[estimate("q", "10.0.0.1", 12345.0)], &info(10));
        assert!(text.contains("# TYPE flowsketch_estimate gauge"));
        assert!(text.contains(
            "flowsketch_estimate{query=\"q\",algorithm=\"spacesaving\",\
             error_kind=\"candidate-upper-bound\",window=\"60s\",src_ip=\"10.0.0.1\"} 12345"
        ));
        assert!(dropped.is_empty());
    }

    #[test]
    fn series_cap_keeps_largest_estimates() {
        let es: Vec<SketchEstimate> = (0..100)
            .map(|i| estimate("q", &format!("10.0.0.{i}"), i as f64))
            .collect();
        let (text, dropped) = render(&es, &info(5));
        assert_eq!(dropped["q"], 95);
        // Largest survive, smallest do not.
        assert!(text.contains("src_ip=\"10.0.0.99\""));
        assert!(!text.contains("src_ip=\"10.0.0.1\","));
        assert!(text.contains("flowsketch_export_series_dropped_total{query=\"q\"} 95"));
    }

    #[test]
    fn label_hygiene() {
        assert_eq!(sanitize_label_name("src.ip"), "src_ip");
        assert_eq!(sanitize_label_name("k8s.pod.name"), "k8s_pod_name");
        assert_eq!(sanitize_label_name("0weird"), "_0weird");
        assert_eq!(escape_label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
