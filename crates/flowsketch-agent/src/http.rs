//! Minimal dependency-free HTTP/1.1 server for the agent's observability
//! surface. Read-only, four routes, connection-per-thread — deliberately
//! boring; the interesting state lives in `PublishedState`.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::state::PublishedState;

pub fn serve_in_background(listener: TcpListener, state: Arc<PublishedState>) {
    std::thread::Builder::new()
        .name("fs-http".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&state);
                let _ = std::thread::Builder::new()
                    .name("fs-http-conn".into())
                    .spawn(move || {
                        let _ = handle_connection(stream, &state);
                    });
            }
        })
        .expect("spawn http thread");
}

fn handle_connection(stream: TcpStream, state: &PublishedState) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    // Drain headers; we don't need them.
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
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
            if state.ready.load(Ordering::Acquire) {
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
