//! Minimal dependency-free HTTP/1.1 server for the gateway: the agent's
//! read-only server plus one POST route for snapshot pushes. Connection-
//! per-thread, bounded request bodies, deliberately boring.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::batch::PushBatch;
use crate::state::GatewayState;

/// Cap on POST bodies. Sketch memory is planner-budgeted (tens of MiB at
/// the extreme), so a larger push is corrupt or hostile, not legitimate.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Accept connections until the process is terminated.
pub fn serve(listener: TcpListener, state: Arc<GatewayState>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let state = Arc::clone(&state);
        let _ = std::thread::Builder::new()
            .name("fs-gw-conn".into())
            .spawn(move || {
                let _ = handle_connection(stream, &state);
            });
    }
}

fn handle_connection(stream: TcpStream, state: &GatewayState) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Drain headers, keeping Content-Length for POST bodies.
    let mut content_length = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
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
        _ => "Unknown",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}
