//! The YAML query DSL (the shape shipped in `examples/queries/`).
//!
//! ```yaml
//! name: suspected_scanners
//! window:
//!   size: 60s
//!   slide: 10s
//! match:
//!   protocol: tcp
//!   dst.port: [22, 80, 443]
//! groupBy:
//!   - src.ip
//! measure:
//!   type: distinct_count
//!   field: dst.ip
//!   error:
//!     epsilon: 0.02
//! alertIf:
//!   gt: 5000
//! export:
//!   prometheus: true
//!   maxSeries: 500
//! resources:
//!   maxMemory: 64MiB
//! ```

use serde::Deserialize;
use thiserror::Error;

use flowsketch_core::event::protocol;
use flowsketch_core::Field;

use crate::logical::{
    AlertSpec, ErrorSpec, ExportSpec, LogicalQuery, Measure, Predicate, WindowSpec,
};

#[derive(Debug, Error)]
pub enum QueryParseError {
    #[error("invalid YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid query: {0}")]
    Invalid(String),
}

/// Parse and validate one query document.
pub fn parse_query_yaml(yaml: &str) -> Result<LogicalQuery, QueryParseError> {
    let raw: RawQuery = serde_yaml::from_str(yaml)?;
    raw.into_logical()
}

const DEFAULT_MAX_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuery {
    name: String,
    window: RawWindow,
    #[serde(default, alias = "where", alias = "match")]
    r#match: Option<RawMatch>,
    #[serde(default, alias = "group_by")]
    #[serde(rename = "groupBy")]
    group_by: Vec<String>,
    measure: RawMeasure,
    #[serde(default, alias = "alert_if")]
    #[serde(rename = "alertIf")]
    alert_if: Option<RawAlert>,
    #[serde(default)]
    export: Option<RawExport>,
    #[serde(default)]
    resources: Option<RawResources>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWindow {
    size: String,
    #[serde(default)]
    slide: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMatch {
    #[serde(default)]
    protocol: Option<serde_yaml::Value>,
    #[serde(default, rename = "dst.port")]
    dst_port: Option<Ports>,
    #[serde(default, rename = "src.port")]
    src_port: Option<Ports>,
    #[serde(default)]
    interfaces: Option<Vec<u32>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Ports {
    One(u16),
    Many(Vec<u16>),
}

impl Ports {
    fn into_vec(self) -> Vec<u16> {
        match self {
            Ports::One(p) => vec![p],
            Ports::Many(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMeasure {
    r#type: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    q: Option<f64>,
    #[serde(default)]
    error: Option<RawError>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawError {
    #[serde(default)]
    epsilon: Option<f64>,
    #[serde(default)]
    delta: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAlert {
    #[serde(default)]
    gt: Option<f64>,
    #[serde(default)]
    lt: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport {
    #[serde(default)]
    prometheus: Option<bool>,
    #[serde(default, alias = "max_series")]
    #[serde(rename = "maxSeries")]
    max_series: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResources {
    #[serde(default, alias = "max_memory")]
    #[serde(rename = "maxMemory")]
    max_memory: Option<String>,
}

impl RawQuery {
    fn into_logical(self) -> Result<LogicalQuery, QueryParseError> {
        if self.name.trim().is_empty() {
            return Err(QueryParseError::Invalid("query name is empty".into()));
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(QueryParseError::Invalid(format!(
                "query name {:?} must be alphanumeric with '_' or '-'",
                self.name
            )));
        }

        let size_nanos = parse_duration(&self.window.size)?;
        let slide_nanos = match &self.window.slide {
            Some(s) => parse_duration(s)?,
            None => size_nanos,
        };
        if slide_nanos == 0 || size_nanos == 0 {
            return Err(QueryParseError::Invalid(
                "window size and slide must be positive".into(),
            ));
        }
        if slide_nanos > size_nanos {
            return Err(QueryParseError::Invalid(
                "window slide must not exceed window size".into(),
            ));
        }
        if size_nanos % slide_nanos != 0 {
            return Err(QueryParseError::Invalid(format!(
                "window size ({}) must be a multiple of slide ({})",
                self.window.size,
                self.window.slide.as_deref().unwrap_or_default()
            )));
        }

        let group_by: Vec<Field> = self
            .group_by
            .iter()
            .map(|s| s.parse::<Field>().map_err(QueryParseError::Invalid))
            .collect::<Result<_, _>>()?;

        let filter = match self.r#match {
            None => Predicate::default(),
            Some(m) => {
                let proto = match m.protocol {
                    None => None,
                    Some(serde_yaml::Value::String(s)) => {
                        Some(protocol::parse(&s).ok_or_else(|| {
                            QueryParseError::Invalid(format!("unknown protocol {s:?}"))
                        })?)
                    }
                    Some(serde_yaml::Value::Number(n)) => {
                        let v = n.as_u64().ok_or_else(|| {
                            QueryParseError::Invalid("protocol number must be 0-255".into())
                        })?;
                        if v > 255 {
                            return Err(QueryParseError::Invalid(
                                "protocol number must be 0-255".into(),
                            ));
                        }
                        Some(v as u8)
                    }
                    Some(other) => {
                        return Err(QueryParseError::Invalid(format!(
                            "protocol must be a name or number, got {other:?}"
                        )))
                    }
                };
                Predicate {
                    protocol: proto,
                    dst_ports: m.dst_port.map(Ports::into_vec).unwrap_or_default(),
                    src_ports: m.src_port.map(Ports::into_vec).unwrap_or_default(),
                    interfaces: m.interfaces.unwrap_or_default(),
                }
            }
        };

        // Defaults depend on the measure family: counting sketches read
        // epsilon as an additive fraction of total weight (0.001), while
        // cardinality sketches read it as a relative standard error, where
        // 0.0163 corresponds to HLL precision 12. An explicitly provided
        // epsilon is always honored as written.
        let default_epsilon = if self.measure.r#type == "distinct_count" {
            0.0163
        } else {
            ErrorSpec::default().epsilon
        };
        let error = match &self.measure.error {
            None => ErrorSpec {
                epsilon: default_epsilon,
                ..ErrorSpec::default()
            },
            Some(e) => ErrorSpec {
                epsilon: e.epsilon.unwrap_or(default_epsilon),
                delta: e.delta.unwrap_or(ErrorSpec::default().delta),
            },
        };
        if !(error.epsilon > 0.0 && error.epsilon < 1.0) {
            return Err(QueryParseError::Invalid(
                "error.epsilon must be in (0, 1)".into(),
            ));
        }
        if !(error.delta > 0.0 && error.delta < 1.0) {
            return Err(QueryParseError::Invalid(
                "error.delta must be in (0, 1)".into(),
            ));
        }

        let parse_field = |name: &Option<String>, what: &str| -> Result<Field, QueryParseError> {
            name.as_deref()
                .ok_or_else(|| {
                    QueryParseError::Invalid(format!(
                        "measure type {:?} requires {what}",
                        self.measure.r#type
                    ))
                })?
                .parse::<Field>()
                .map_err(QueryParseError::Invalid)
        };

        let measure = match self.measure.r#type.as_str() {
            "count" => Measure::Count,
            "sum" => {
                let value = parse_field(
                    &self.measure.value.clone().or(self.measure.field.clone()),
                    "a numeric `value` field",
                )?;
                if !value.is_numeric_measure() {
                    return Err(QueryParseError::Invalid(format!(
                        "sum requires a numeric field (bytes or packets), got {value}"
                    )));
                }
                Measure::Sum { value }
            }
            "heavy_hitters" => {
                let value = parse_field(&self.measure.value, "a numeric `value` field")?;
                if !value.is_numeric_measure() {
                    return Err(QueryParseError::Invalid(format!(
                        "heavy_hitters requires a numeric value field (bytes or packets), got {value}"
                    )));
                }
                let limit = self.measure.limit.unwrap_or(100);
                if limit == 0 {
                    return Err(QueryParseError::Invalid(
                        "heavy_hitters limit must be positive".into(),
                    ));
                }
                Measure::HeavyHitters { value, limit }
            }
            "distinct_count" => Measure::DistinctCount {
                field: parse_field(&self.measure.field, "a `field` to count distinct values of")?,
            },
            "entropy" => Measure::Entropy {
                field: parse_field(&self.measure.field, "a `field`")?,
            },
            "quantile" => {
                let field = parse_field(&self.measure.field, "a numeric `field`")?;
                if !field.is_numeric_measure() {
                    return Err(QueryParseError::Invalid(format!(
                        "quantile requires a numeric field (bytes or packets), got {field}"
                    )));
                }
                Measure::Quantile {
                    field,
                    q: self.measure.q.unwrap_or(0.5),
                }
            }
            other => {
                return Err(QueryParseError::Invalid(format!(
                    "unknown measure type {other:?}; expected count, sum, heavy_hitters, \
                     distinct_count, entropy, or quantile"
                )))
            }
        };

        if matches!(measure, Measure::HeavyHitters { .. }) && group_by.is_empty() {
            return Err(QueryParseError::Invalid(
                "heavy_hitters requires groupBy fields (the identities to rank)".into(),
            ));
        }
        if let Measure::DistinctCount { field } = &measure {
            if group_by.contains(field) {
                return Err(QueryParseError::Invalid(format!(
                    "distinct_count field {field} must not also appear in groupBy"
                )));
            }
        }

        let alert = match self.alert_if {
            None => AlertSpec::default(),
            Some(a) => AlertSpec { gt: a.gt, lt: a.lt },
        };

        let default_export = ExportSpec::default();
        let export = match self.export {
            None => default_export,
            Some(e) => ExportSpec {
                prometheus: e.prometheus.unwrap_or(default_export.prometheus),
                max_series: e.max_series.unwrap_or(default_export.max_series),
            },
        };
        if export.max_series == 0 {
            return Err(QueryParseError::Invalid(
                "export.maxSeries must be positive".into(),
            ));
        }

        let max_memory_bytes = match self.resources.and_then(|r| r.max_memory) {
            None => DEFAULT_MAX_MEMORY_BYTES,
            Some(s) => parse_memory(&s)?,
        };

        Ok(LogicalQuery {
            name: self.name,
            filter,
            group_by,
            measure,
            window: WindowSpec {
                size_nanos,
                slide_nanos,
            },
            error,
            alert,
            export,
            max_memory_bytes,
        })
    }
}

/// Parse durations like `10s`, `5m`, `1h`, `500ms`.
pub fn parse_duration(s: &str) -> Result<u64, QueryParseError> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| QueryParseError::Invalid(format!("duration {s:?} is missing a unit")))?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| QueryParseError::Invalid(format!("invalid duration {s:?}")))?;
    let scale = match unit {
        "ns" => 1,
        "us" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 3_600 * 1_000_000_000,
        other => {
            return Err(QueryParseError::Invalid(format!(
                "unknown duration unit {other:?} in {s:?}"
            )))
        }
    };
    Ok(n * scale)
}

/// Parse memory sizes like `128MiB`, `64KiB`, `1GiB`, `4096B`.
pub fn parse_memory(s: &str) -> Result<u64, QueryParseError> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| QueryParseError::Invalid(format!("memory size {s:?} is missing a unit")))?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| QueryParseError::Invalid(format!("invalid memory size {s:?}")))?;
    let scale = match unit {
        "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        other => {
            return Err(QueryParseError::Invalid(format!(
                "unknown memory unit {other:?} in {s:?} (use B, KiB, MiB, GiB)"
            )))
        }
    };
    Ok(n * scale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowsketch_core::event::protocol as proto;

    #[test]
    fn parses_top_talkers() {
        let q = parse_query_yaml(
            r#"
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
"#,
        )
        .unwrap();
        assert_eq!(q.name, "top_talkers");
        assert_eq!(q.window.size_nanos, 60_000_000_000);
        assert_eq!(q.window.slide_nanos, 10_000_000_000);
        assert_eq!(q.window.bucket_count(), 6);
        assert_eq!(q.group_by, vec![Field::SrcIp, Field::DstIp]);
        assert_eq!(
            q.measure,
            Measure::HeavyHitters {
                value: Field::Bytes,
                limit: 100
            }
        );
    }

    #[test]
    fn parses_scanner_query_with_filter_and_alert() {
        let q = parse_query_yaml(
            r#"
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
  error:
    epsilon: 0.02
alertIf:
  gt: 5000
export:
  maxSeries: 500
resources:
  maxMemory: 64MiB
"#,
        )
        .unwrap();
        assert_eq!(q.filter.protocol, Some(proto::TCP));
        assert_eq!(q.filter.dst_ports, vec![22, 80, 443, 5432, 6379]);
        assert_eq!(
            q.measure,
            Measure::DistinctCount {
                field: Field::DstIp
            }
        );
        assert_eq!(q.alert.gt, Some(5000.0));
        assert_eq!(q.export.max_series, 500);
        assert_eq!(q.max_memory_bytes, 64 * 1024 * 1024);
        assert_eq!(q.error.epsilon, 0.02);
    }

    #[test]
    fn distinct_count_gets_cardinality_default_epsilon() {
        let q = parse_query_yaml(
            "name: d\nwindow: {size: 60s}\ngroupBy: [src.ip]\n\
             measure: {type: distinct_count, field: dst.ip}\n",
        )
        .unwrap();
        assert_eq!(q.error.epsilon, 0.0163);

        // Explicit epsilon survives as written, even when very tight.
        let q = parse_query_yaml(
            "name: d\nwindow: {size: 60s}\ngroupBy: [src.ip]\n\
             measure: {type: distinct_count, field: dst.ip, error: {epsilon: 0.0005}}\n",
        )
        .unwrap();
        assert_eq!(q.error.epsilon, 0.0005);
    }

    #[test]
    fn tumbling_window_when_slide_omitted() {
        let q = parse_query_yaml(
            "name: t\nwindow:\n  size: 30s\ngroupBy: [protocol]\nmeasure:\n  type: count\n",
        )
        .unwrap();
        assert_eq!(q.window.slide_nanos, q.window.size_nanos);
        assert_eq!(q.window.bucket_count(), 1);
    }

    #[test]
    fn rejects_bad_queries() {
        // Unknown field
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 10s}\ngroupBy: [nonsense]\nmeasure: {type: count}\n"
        )
        .is_err());
        // Slide > size
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 10s, slide: 20s}\ngroupBy: [src.ip]\nmeasure: {type: count}\n"
        )
        .is_err());
        // Non-divisible slide
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 60s, slide: 25s}\ngroupBy: [src.ip]\nmeasure: {type: count}\n"
        )
        .is_err());
        // heavy_hitters without groupBy
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 10s}\nmeasure: {type: heavy_hitters, value: bytes}\n"
        )
        .is_err());
        // distinct_count field also in groupBy
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 10s}\ngroupBy: [dst.ip]\nmeasure: {type: distinct_count, field: dst.ip}\n"
        )
        .is_err());
        // Unknown measure
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 10s}\ngroupBy: [src.ip]\nmeasure: {type: median}\n"
        )
        .is_err());
        // Non-numeric quantile field (would silently produce zero quantiles)
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 10s}\nmeasure: {type: quantile, field: src.ip, q: 0.9}\n"
        )
        .is_err());
        // Unknown top-level key
        assert!(parse_query_yaml(
            "name: q\nwindow: {size: 10s}\ngroupBy: [src.ip]\nmeasure: {type: count}\nbogus: 1\n"
        )
        .is_err());
    }

    #[test]
    fn duration_and_memory_parsing() {
        assert_eq!(parse_duration("10s").unwrap(), 10_000_000_000);
        assert_eq!(parse_duration("5m").unwrap(), 300_000_000_000);
        assert_eq!(parse_duration("500ms").unwrap(), 500_000_000);
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("10parsecs").is_err());
        assert_eq!(parse_memory("64MiB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_memory("1GiB").unwrap(), 1 << 30);
        assert!(parse_memory("64MB").is_err());
    }

    #[test]
    fn helm_default_queries_are_valid_and_uniquely_named() {
        let values = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/helm/flowsketch/values.yaml");
        let yaml = std::fs::read_to_string(&values).unwrap();
        let document: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let queries = document["queries"]
            .as_mapping()
            .expect("chart values must contain a queries map");
        assert!(!queries.is_empty());
        let mut names = std::collections::BTreeSet::new();
        for (filename, source) in queries {
            let filename = filename.as_str().expect("query filename must be text");
            let source = source.as_str().expect("query source must be text");
            let query = parse_query_yaml(source)
                .unwrap_or_else(|error| panic!("invalid Helm query {filename}: {error}"));
            assert!(
                names.insert(query.name.clone()),
                "duplicate Helm query name {:?}",
                query.name
            );
        }
    }
}
