//! Minimal OTLP/HTTP client: POST JSON to `/v1/metrics` with retry and
//! exponential backoff. Deliberately dependency-free (std TCP + HTTP/1.1);
//! plain `http://` only — the expected peer is a local collector.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtlpClientError {
    #[error("invalid endpoint {0:?} (expected http://host:port[/v1/metrics])")]
    BadEndpoint(String),
    #[error("connect to {0} failed: {1}")]
    Connect(String, std::io::Error),
    #[error("io error talking to {0}: {1}")]
    Io(String, std::io::Error),
    #[error("collector returned HTTP {0}")]
    Status(u16),
    #[error("encoded OTLP request body is {bytes} bytes, above the {max} byte cap")]
    BodyTooLarge { bytes: usize, max: usize },
    #[error("gave up after {attempts} attempts; last error: {last}")]
    RetriesExhausted { attempts: u32, last: String },
}

const MAX_ENDPOINT_LEN: usize = 2_048;
const MAX_OTLP_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_HTTP_RESPONSE_BYTES: u64 = 16 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse `http://host:port/path` into (authority, path).
fn parse_url(url: &str) -> Result<(String, String), OtlpClientError> {
    if url.len() > MAX_ENDPOINT_LEN {
        return Err(OtlpClientError::BadEndpoint(url.to_string()));
    }
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| OtlpClientError::BadEndpoint(url.to_string()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty()
        || authority.bytes().any(|b| b <= b' ' || b == 0x7f)
        || path.bytes().any(|b| b <= b' ' || b == 0x7f)
    {
        return Err(OtlpClientError::BadEndpoint(url.to_string()));
    }
    Ok((authority.to_string(), path.to_string()))
}

/// One POST attempt. Returns the HTTP status code.
fn post_once(url: &str, body: &[u8], timeout: Duration) -> Result<u16, OtlpClientError> {
    let (authority, path) = parse_url(url)?;
    let mut last_connect_error = None;
    let mut stream = None;
    for addr in authority
        .to_socket_addrs()
        .map_err(|e| OtlpClientError::Connect(authority.clone(), e))?
    {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_connect_error = Some(e),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        OtlpClientError::Connect(
            authority.clone(),
            last_connect_error.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no socket addresses")
            }),
        )
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| OtlpClientError::Io(authority.clone(), e))?;

    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|e| OtlpClientError::Io(authority.clone(), e))?;

    let mut response = Vec::new();
    // Read until close, bounded; only the status line matters.
    (&mut stream)
        .take(MAX_HTTP_RESPONSE_BYTES)
        .read_to_end(&mut response)
        .map_err(|e| OtlpClientError::Io(authority.clone(), e))?;
    let status_line = response.split(|&b| b == b'\n').next().unwrap_or_default();
    let status: u16 = std::str::from_utf8(status_line)
        .ok()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            OtlpClientError::Io(
                authority.clone(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, "unparseable HTTP response"),
            )
        })?;
    Ok(status)
}

/// POST an encoded OTLP document, retrying transient failures with
/// exponential backoff (200ms, 800ms, 3200ms). Per the OTLP/HTTP spec,
/// only 429, 502, 503, and 504 are retryable; every other non-2xx status
/// is final — the payload will not get more acceptable by resending it.
pub fn post_metrics(url: &str, document: &serde_json::Value) -> Result<(), OtlpClientError> {
    let body = serde_json::to_vec(document).expect("json value serializes");
    if body.len() > MAX_OTLP_BODY_BYTES {
        return Err(OtlpClientError::BodyTooLarge {
            bytes: body.len(),
            max: MAX_OTLP_BODY_BYTES,
        });
    }
    let mut last_error = String::new();
    let mut backoff = Duration::from_millis(200);
    const ATTEMPTS: u32 = 3;

    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(backoff);
            backoff *= 4;
        }
        match post_once(url, &body, HTTP_TIMEOUT) {
            Ok(status) if (200..300).contains(&status) => return Ok(()),
            // OTLP retryable set: rate limiting and gateway pressure.
            Ok(status @ (429 | 502 | 503 | 504)) => last_error = format!("HTTP {status}"),
            Ok(status) => return Err(OtlpClientError::Status(status)),
            Err(e @ OtlpClientError::BadEndpoint(_)) => return Err(e),
            Err(e) => last_error = e.to_string(),
        }
    }
    Err(OtlpClientError::RetriesExhausted {
        attempts: ATTEMPTS,
        last: last_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::net::TcpListener;

    /// A one-shot fake collector: accepts one request, returns `status`,
    /// and hands back the request body.
    fn fake_collector(status: u16) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(&stream);
            let mut content_length = 0usize;
            let mut line = String::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap();
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = reader.into_inner();
            write!(stream, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n").unwrap();
            String::from_utf8(body).unwrap()
        });
        (format!("http://{addr}/v1/metrics"), handle)
    }

    #[test]
    fn posts_json_and_succeeds_on_2xx() {
        let (url, handle) = fake_collector(200);
        let doc = serde_json::json!({"resourceMetrics": []});
        post_metrics(&url, &doc).unwrap();
        let body = handle.join().unwrap();
        assert!(body.contains("resourceMetrics"));
    }

    /// A fake collector that serves one request per status in `statuses`,
    /// returning how many requests it actually saw.
    fn fake_collector_seq(statuses: Vec<u16>) -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut served = 0usize;
            for status in statuses {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                let mut reader = std::io::BufReader::new(&stream);
                let mut content_length = 0usize;
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                let mut stream = reader.into_inner();
                let _ = write!(stream, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n");
                served += 1;
            }
            served
        });
        (format!("http://{addr}/v1/metrics"), handle)
    }

    #[test]
    fn client_error_is_not_retried() {
        let (url, handle) = fake_collector(400);
        let err = post_metrics(&url, &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, OtlpClientError::Status(400)), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn rate_limiting_is_retried_with_backoff() {
        // OTLP spec: 429 is retryable. First attempt gets throttled, the
        // retry succeeds.
        let (url, handle) = fake_collector_seq(vec![429, 200]);
        post_metrics(&url, &serde_json::json!({})).unwrap();
        assert_eq!(handle.join().unwrap(), 2, "expected exactly one retry");
    }

    #[test]
    fn server_error_500_is_not_retried() {
        // OTLP spec: only 429/502/503/504 are retryable; a plain 500 is
        // final.
        let (url, handle) = fake_collector_seq(vec![500]);
        let err = post_metrics(&url, &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, OtlpClientError::Status(500)), "{err}");
        assert_eq!(handle.join().unwrap(), 1);
    }

    #[test]
    fn bad_gateway_retries_until_exhausted() {
        let (url, handle) = fake_collector_seq(vec![503, 503, 503]);
        let err = post_metrics(&url, &serde_json::json!({})).unwrap_err();
        assert!(
            matches!(err, OtlpClientError::RetriesExhausted { attempts: 3, .. }),
            "{err}"
        );
        assert_eq!(handle.join().unwrap(), 3);
    }

    #[test]
    fn unreachable_collector_exhausts_retries() {
        // Reserved port with no listener; connect fails fast.
        let err = post_metrics("http://127.0.0.1:1/v1/metrics", &serde_json::json!({}));
        assert!(matches!(
            err,
            Err(OtlpClientError::RetriesExhausted { attempts: 3, .. })
        ));
    }

    #[test]
    fn rejects_non_http_endpoints() {
        let err = post_metrics("https://collector:4318", &serde_json::json!({}));
        assert!(matches!(err, Err(OtlpClientError::BadEndpoint(_))));
    }

    #[test]
    fn rejects_malformed_http_endpoints() {
        let err = post_metrics("http://local host:4318/v1/metrics", &serde_json::json!({}));
        assert!(matches!(err, Err(OtlpClientError::BadEndpoint(_))));

        let long = format!("http://{}:4318/v1/metrics", "a".repeat(MAX_ENDPOINT_LEN));
        let err = post_metrics(&long, &serde_json::json!({}));
        assert!(matches!(err, Err(OtlpClientError::BadEndpoint(_))));
    }

    #[test]
    fn rejects_oversized_request_body_before_connecting() {
        let doc = serde_json::json!({ "payload": "x".repeat(MAX_OTLP_BODY_BYTES) });
        let err = post_metrics("http://127.0.0.1:1/v1/metrics", &doc);
        assert!(matches!(
            err,
            Err(OtlpClientError::BodyTooLarge {
                max: MAX_OTLP_BODY_BYTES,
                ..
            })
        ));
    }
}
