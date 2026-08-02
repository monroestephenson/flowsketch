//! Minimal dependency-free HTTP/1.1 server for the agent's observability
//! surface. Read-only, four routes, bounded connection-per-thread — the
//! interesting state lives in `PublishedState`.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::state::PublishedState;

const MAX_CONCURRENT_CONNECTIONS: usize = 128;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(11);

pub fn serve_in_background(
    listener: TcpListener,
    state: Arc<PublishedState>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
    listener.set_nonblocking(true)?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new()
        .name("fs-http".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                if !try_acquire_connection(&active_connections) {
                    let _ = respond(stream, 503, "text/plain", "server busy\n");
                    continue;
                }
                let state = Arc::clone(&state);
                let active = Arc::clone(&active_connections);
                let spawn = std::thread::Builder::new()
                    .name("fs-http-conn".into())
                    .spawn(move || {
                        let _guard = ConnectionGuard(active);
                        let _ = handle_connection(stream, &state);
                    });
                if spawn.is_err() {
                    active_connections.fetch_sub(1, Ordering::AcqRel);
                }
            }
            wait_for_connections(&active_connections, CONNECTION_DRAIN_TIMEOUT)
        })
}

fn handle_connection(stream: TcpStream, state: &PublishedState) -> std::io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let request_line = match read_line_bounded(&mut reader, MAX_REQUEST_LINE_BYTES) {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            return respond(stream, 400, "text/plain", "bad request\n")
        }
        Err(e) => return Err(e),
    };

    let mut header_bytes = 0usize;
    loop {
        let line = match read_line_bounded(&mut reader, MAX_HEADER_LINE_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                return respond(stream, 431, "text/plain", "request headers too large\n")
            }
            Err(e) => return Err(e),
        };
        header_bytes += line.len();
        if header_bytes > MAX_HEADER_BYTES {
            return respond(stream, 431, "text/plain", "request headers too large\n");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let (status, content_type, body) = route(method, path, state);
    respond(stream, status, content_type, &body)
}

fn route(method: &str, path: &str, state: &PublishedState) -> (u16, &'static str, String) {
    if method != "GET" {
        return (405, "text/plain", "method not allowed\n".into());
    }
    match path {
        "/healthz" => {
            if let Some(err) = state.source_error.lock().unwrap().as_ref() {
                (503, "text/plain", format!("capture source failed: {err}\n"))
            } else {
                (200, "text/plain", "ok\n".into())
            }
        }
        "/readyz" => {
            if state.source_error.lock().unwrap().is_some() {
                (503, "text/plain", "capture source failed\n".into())
            } else if state.ready.load(Ordering::Acquire) {
                (200, "text/plain", "ready\n".into())
            } else {
                (503, "text/plain", "starting\n".into())
            }
        }
        "/metrics" => {
            let estimates = state.latest_estimates();
            let (mut body, _) = flowsketch_prometheus::render(&estimates, &state.export_info());
            body.push_str(&state.render_health_metrics());
            (200, "text/plain; version=0.0.4", body)
        }
        "/v1/queries" => {
            let queries: Vec<serde_json::Value> = state
                .queries
                .iter()
                .map(|q| {
                    serde_json::json!({
                        "name": q.name,
                        "algorithm": q.algorithm,
                        "window": q.window,
                        "errorKind": q.error_kind,
                        "errorContract": q.error_contract,
                        "estimatedMemoryBytes": q.estimated_memory_bytes,
                        "maxSeries": q.max_series,
                    })
                })
                .collect();
            (
                200,
                "application/json",
                serde_json::to_string_pretty(&queries).unwrap_or_else(|_| "[]".into()),
            )
        }
        _ => (404, "text/plain", "not found\n".into()),
    }
}

fn respond(
    mut stream: TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        400 => "Bad Request",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn try_acquire_connection(active: &AtomicUsize) -> bool {
    loop {
        let current = active.load(Ordering::Acquire);
        if current >= MAX_CONCURRENT_CONNECTIONS {
            return false;
        }
        if active
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn wait_for_connections(active: &AtomicUsize, timeout: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + timeout;
    while active.load(Ordering::Acquire) != 0 {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{} agent HTTP connection(s) did not drain before shutdown",
                    active.load(Ordering::Acquire)
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
            };
        }
        let take = available
            .iter()
            .position(|&b| b == b'\n')
            .map_or(available.len(), |pos| pos + 1);
        if buf.len() + take > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP line too long",
            ));
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
        if buf.ends_with(b"\n") {
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_line_reader_rejects_oversized_lines() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"GET / HTTP/1.1\r\n"));
        let err = read_line_bounded(&mut reader, 4).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn bounded_line_reader_accepts_normal_lines() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"GET / HTTP/1.1\r\n"));
        let line = read_line_bounded(&mut reader, 1024).unwrap().unwrap();
        assert_eq!(line, "GET / HTTP/1.1\r\n");
    }

    #[test]
    fn readiness_fails_after_capture_source_error() {
        let state = PublishedState::new(&[], 1, None, 0);
        assert_eq!(route("GET", "/readyz", &state).0, 503);
        state.ready.store(true, Ordering::Release);
        assert_eq!(route("GET", "/readyz", &state).0, 200);
        *state.source_error.lock().unwrap() = Some("attach failed".into());
        assert_eq!(route("GET", "/readyz", &state).0, 503);
    }

    #[test]
    fn connection_drain_reports_a_stuck_worker() {
        let active = AtomicUsize::new(1);
        let error = wait_for_connections(&active, Duration::ZERO).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        active.store(0, Ordering::Release);
        wait_for_connections(&active, Duration::ZERO).unwrap();
    }
}
