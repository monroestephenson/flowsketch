//! The agent-side push client: POST an encoded `FSKB` batch to the
//! gateway's `/v1/snapshots` with retry and exponential backoff.
//! Deliberately dependency-free (std TCP + HTTP/1.1), plain `http://`
//! only — the expected peer is an in-cluster gateway, mirroring the OTLP
//! exporter's posture.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use thiserror::Error;

/// Agent configuration for pushing snapshots to a gateway (mirrors the
/// agent's `export.gateway` YAML block).
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// Gateway base endpoint, e.g. `http://flowsketch-gateway:9465`.
    /// `/v1/snapshots` is appended automatically if missing.
    pub endpoint: String,
    /// How often the agent pushes its current window snapshots.
    pub interval_ms: u64,
}

impl PushConfig {
    /// The full snapshot-push URL for this endpoint.
    pub fn snapshots_url(&self) -> String {
        let base = self.endpoint.trim_end_matches('/');
        if base.ends_with("/v1/snapshots") {
            base.to_string()
        } else {
            format!("{base}/v1/snapshots")
        }
    }
}

#[derive(Debug, Error)]
pub enum PushClientError {
    #[error("invalid endpoint {0:?} (expected http://host:port[/v1/snapshots])")]
    BadEndpoint(String),
    #[error("connect to {0} failed: {1}")]
    Connect(String, std::io::Error),
    #[error("io error talking to {0}: {1}")]
    Io(String, std::io::Error),
    #[error("gateway returned HTTP {0}")]
    Status(u16),
    #[error("gave up after {attempts} attempts; last error: {last}")]
    RetriesExhausted { attempts: u32, last: String },
}

/// Parse `http://host:port/path` into (authority, path).
fn parse_url(url: &str) -> Result<(String, String), PushClientError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| PushClientError::BadEndpoint(url.to_string()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(PushClientError::BadEndpoint(url.to_string()));
    }
    Ok((authority.to_string(), path.to_string()))
}

/// One POST attempt. Returns the HTTP status code.
fn post_once(url: &str, body: &[u8], timeout: Duration) -> Result<u16, PushClientError> {
    let (authority, path) = parse_url(url)?;
    let mut stream = TcpStream::connect(&authority)
        .map_err(|e| PushClientError::Connect(authority.clone(), e))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| PushClientError::Io(authority.clone(), e))?;

    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|e| PushClientError::Io(authority.clone(), e))?;

    let mut response = Vec::new();
    // Read until close; only the status line matters.
    let _ = stream.take(16 * 1024).read_to_end(&mut response);
    let status_line = response.split(|&b| b == b'\n').next().unwrap_or_default();
    let status: u16 = std::str::from_utf8(status_line)
        .ok()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            PushClientError::Io(
                authority.clone(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, "unparseable HTTP response"),
            )
        })?;
    Ok(status)
}

/// POST an encoded push batch, retrying transient failures with
/// exponential backoff (200ms, 800ms, 3200ms). Only 429, 502, 503, and
/// 504 are retryable; a 400 means the batch itself was rejected
/// (incompatible sketches, unknown query) and will not get more
/// acceptable by resending it.
pub fn push_batch(url: &str, body: &[u8]) -> Result<(), PushClientError> {
    let mut last_error = String::new();
    let mut backoff = Duration::from_millis(200);
    const ATTEMPTS: u32 = 3;

    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(backoff);
            backoff *= 4;
        }
        match post_once(url, body, Duration::from_secs(5)) {
            Ok(status) if (200..300).contains(&status) => return Ok(()),
            Ok(status @ (429 | 502 | 503 | 504)) => last_error = format!("HTTP {status}"),
            Ok(status) => return Err(PushClientError::Status(status)),
            Err(e @ PushClientError::BadEndpoint(_)) => return Err(e),
            Err(e) => last_error = e.to_string(),
        }
    }
    Err(PushClientError::RetriesExhausted {
        attempts: ATTEMPTS,
        last: last_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_url_appends_path_once() {
        let cfg = PushConfig {
            endpoint: "http://gw:9465".into(),
            interval_ms: 1000,
        };
        assert_eq!(cfg.snapshots_url(), "http://gw:9465/v1/snapshots");
        let cfg = PushConfig {
            endpoint: "http://gw:9465/v1/snapshots".into(),
            interval_ms: 1000,
        };
        assert_eq!(cfg.snapshots_url(), "http://gw:9465/v1/snapshots");
    }

    #[test]
    fn rejects_non_http_endpoints() {
        let err = push_batch("https://gw:9465/v1/snapshots", &[]).unwrap_err();
        assert!(matches!(err, PushClientError::BadEndpoint(_)));
    }

    #[test]
    fn unreachable_gateway_exhausts_retries() {
        let err = push_batch("http://127.0.0.1:1/v1/snapshots", &[]).unwrap_err();
        assert!(matches!(
            err,
            PushClientError::RetriesExhausted { attempts: 3, .. }
        ));
    }
}
