//! Minimal dependency-free HTTP/1.1 server for the gateway: the agent's
//! read-only server plus one POST route for snapshot pushes. Bounded
//! connection-per-thread, bounded request bodies, deliberately boring.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::batch::PushBatch;
use crate::state::GatewayState;

/// Cap on POST bodies. Sketch memory is planner-budgeted (tens of MiB at
/// the extreme), so a larger push is corrupt or hostile, not legitimate.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 128;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept connections until the process is terminated.
pub fn serve(listener: TcpListener, state: Arc<GatewayState>) -> std::io::Result<()> {
    let active_connections = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = stream?;
        if !try_acquire_connection(&active_connections) {
            let _ = respond(stream, 503, "text/plain", "server busy\n");
            continue;
        }
        let state = Arc::clone(&state);
        let active = Arc::clone(&active_connections);
        let spawn = std::thread::Builder::new()
            .name("fs-gw-conn".into())
            .spawn(move || {
                let _guard = ConnectionGuard(active);
                let _ = handle_connection(stream, &state);
            });
        if spawn.is_err() {
            active_connections.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

fn handle_connection(stream: TcpStream, state: &GatewayState) -> std::io::Result<()> {
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

    // Drain headers, keeping Content-Length for POST bodies.
    let mut content_length = 0usize;
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
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let (status, content_type, body) = match (method, path) {
        ("POST", "/v1/snapshots") => {
            if content_length == 0 {
                (400, "text/plain", "empty body\n".to_string())
            } else if content_length > MAX_BODY_BYTES {
                (413, "text/plain", "body too large\n".to_string())
            } else {
                let mut body = vec![0u8; content_length];
                match reader.read_exact(&mut body) {
                    Ok(()) => receive_snapshots(&body, state),
                    Err(_) => (400, "text/plain", "truncated body\n".to_string()),
                }
            }
        }
        _ => route_get(method, path, state),
    };
    respond(stream, status, content_type, &body)
}

fn receive_snapshots(body: &[u8], state: &GatewayState) -> (u16, &'static str, String) {
    let batch = match PushBatch::decode(body) {
        Ok(b) => b,
        Err(e) => return (400, "text/plain", format!("invalid push batch: {e}\n")),
    };
    let result = state.apply_batch(&batch);
    let response = serde_json::json!({
        "accepted": result.accepted,
        "rejected": result.rejected,
    });
    // Nothing usable in the batch is the pusher's error; partial accepts
    // are a 200 with the rejects listed so a misconfigured query is
    // visible without failing healthy ones.
    let status = if result.accepted == 0 && !result.rejected.is_empty() {
        400
    } else {
        200
    };
    (status, "application/json", response.to_string())
}

fn route_get(method: &str, path: &str, state: &GatewayState) -> (u16, &'static str, String) {
    if method != "GET" {
        return (405, "text/plain", "method not allowed\n".into());
    }
    match path {
        "/healthz" => (200, "text/plain", "ok\n".into()),
        "/readyz" => (200, "text/plain", "ready\n".into()),
        "/metrics" => (200, "text/plain; version=0.0.4", state.render_metrics()),
        "/v1/queries" => (
            200,
            "application/json",
            serde_json::to_string_pretty(&state.queries_json()).unwrap_or_else(|_| "[]".into()),
        ),
        "/v1/nodes" => (
            200,
            "application/json",
            serde_json::to_string_pretty(&state.nodes_json()).unwrap_or_else(|_| "[]".into()),
        ),
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
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
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
