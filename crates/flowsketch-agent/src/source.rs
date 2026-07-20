//! Capture sources: pcap replay, AF_PACKET TPACKET_V3, and Linux tc eBPF.

#[cfg(target_os = "linux")]
mod af_packet;

use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use flowsketch_core::FlowEvent;
use flowsketch_pcap::PcapReader;
#[cfg(target_os = "linux")]
use flowsketch_pcap::{linktype, parse_packet};

use crate::config::{
    default_block_retire_timeout_ms, default_ring_block_count, default_ring_block_size_bytes,
    SourceConfig,
};
#[cfg(target_os = "linux")]
use crate::offer_event;
use crate::state::PublishedState;
use crate::AgentError;

#[cfg(target_os = "linux")]
const AF_PACKET_STATS_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const EBPF_POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const EBPF_STATS_INTERVAL: Duration = Duration::from_secs(1);

pub fn capture_loop(
    source: SourceConfig,
    tx: SyncSender<FlowEvent>,
    state: Arc<PublishedState>,
) -> Result<(), AgentError> {
    let result = match source {
        SourceConfig::Pcap { path } => pcap_loop(&path, &tx, &state),
        SourceConfig::AfPacket {
            interface,
            ring_block_size_bytes,
            ring_block_count,
            block_retire_timeout_ms,
        } => af_packet_loop(
            &interface,
            ring_block_size_bytes,
            ring_block_count,
            block_retire_timeout_ms,
            &tx,
            &state,
        ),
        SourceConfig::Ebpf {
            interface,
            object_path,
            ring_buffer_bytes,
            fallback_to_af_packet,
        } => match ebpf_loop(&interface, &object_path, ring_buffer_bytes, &tx, &state) {
            Ok(()) => Ok(()),
            Err(error) if fallback_to_af_packet => {
                state.ebpf_fallbacks.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "eBPF capture failed; explicitly configured AF_PACKET fallback is starting: {error}"
                );
                af_packet_loop(
                    &interface,
                    default_ring_block_size_bytes(),
                    default_ring_block_count(),
                    default_block_retire_timeout_ms(),
                    &tx,
                    &state,
                )
            }
            Err(error) => Err(error),
        },
    };
    if let Err(e) = &result {
        *state.source_error.lock().unwrap() = Some(e.to_string());
    }
    result
}

#[cfg(target_os = "linux")]
fn ebpf_loop(
    interface: &str,
    object_path: &std::path::Path,
    ring_buffer_bytes: u32,
    tx: &SyncSender<FlowEvent>,
    state: &PublishedState,
) -> Result<(), AgentError> {
    let mut collector =
        flowsketch_ebpf::TcCollector::attach(interface, object_path, ring_buffer_bytes).map_err(
            |error| AgentError::Source(format!("tc eBPF source on {interface}: {error}")),
        )?;
    state
        .ebpf_ring_bytes
        .store(u64::from(ring_buffer_bytes), Ordering::Relaxed);
    let mut last_statistics = Instant::now();

    loop {
        let mut packets_seen = 0u64;
        let mut packets_parsed = 0u64;
        let mut packets_unparsed = 0u64;
        let mut conversion_error = None;
        let keep_running = collector
            .poll(EBPF_POLL_INTERVAL, |record| {
                packets_seen += 1;
                match FlowEvent::try_from(record) {
                    Ok(event) => {
                        packets_parsed += 1;
                        offer_event(tx, event, state)
                    }
                    Err(error) => {
                        packets_unparsed += 1;
                        conversion_error = Some(error);
                        false
                    }
                }
            })
            .map_err(|error| {
                AgentError::Source(format!("tc eBPF receive on {interface}: {error}"))
            })?;
        if packets_seen != 0 {
            state
                .packets_seen
                .fetch_add(packets_seen, Ordering::Relaxed);
            state
                .packets_parsed
                .fetch_add(packets_parsed, Ordering::Relaxed);
            state
                .packets_unparsed
                .fetch_add(packets_unparsed, Ordering::Relaxed);
        }
        if let Some(error) = conversion_error {
            return Err(AgentError::Source(format!(
                "tc eBPF ABI record on {interface} is invalid: {error}"
            )));
        }
        if last_statistics.elapsed() >= EBPF_STATS_INTERVAL {
            record_ebpf_statistics(&collector, state, interface)?;
            last_statistics = Instant::now();
        }
        if !keep_running {
            record_ebpf_statistics(&collector, state, interface)?;
            return Ok(());
        }
    }
}

#[cfg(target_os = "linux")]
fn record_ebpf_statistics(
    collector: &flowsketch_ebpf::TcCollector,
    state: &PublishedState,
    interface: &str,
) -> Result<(), AgentError> {
    let counters = collector
        .counters()
        .map_err(|error| AgentError::Source(format!("tc eBPF counters on {interface}: {error}")))?;
    state
        .ebpf_packets
        .store(counters.packets, Ordering::Relaxed);
    state
        .ebpf_events_emitted
        .store(counters.emitted, Ordering::Relaxed);
    state
        .ebpf_ring_dropped_events
        .store(counters.ring_drops, Ordering::Relaxed);
    state
        .ebpf_parse_errors
        .store(counters.parse_errors, Ordering::Relaxed);
    state
        .ebpf_unsupported_packets
        .store(counters.unsupported, Ordering::Relaxed);
    Ok(())
}

fn pcap_loop(
    path: &std::path::Path,
    tx: &SyncSender<FlowEvent>,
    state: &PublishedState,
) -> Result<(), AgentError> {
    let file = std::fs::File::open(path)
        .map_err(|e| AgentError::Source(format!("cannot open {}: {e}", path.display())))?;
    let mut reader = PcapReader::new(std::io::BufReader::new(file))
        .map_err(|e| AgentError::Source(e.to_string()))?;
    let mut packet_buf = Vec::with_capacity(2048);
    while let Some(event) = reader
        .next_event_into(&mut packet_buf)
        .map_err(|e| AgentError::Source(e.to_string()))?
    {
        state.packets_seen.fetch_add(1, Ordering::Relaxed);
        state.packets_parsed.fetch_add(1, Ordering::Relaxed);
        // File replay has no liveness constraint: block (backpressure)
        // rather than drop, so results cover the whole trace. Live capture
        // (af_packet) uses the non-blocking drop-and-count path instead.
        if tx.send(event).is_err() {
            break; // engine gone
        }
    }
    Ok(())
}

/// AF_PACKET live capture. Linux only; other platforms return a clear
/// configuration/runtime error.
#[cfg(target_os = "linux")]
fn af_packet_loop(
    interface: &str,
    ring_block_size_bytes: u32,
    ring_block_count: u32,
    block_retire_timeout_ms: u32,
    tx: &SyncSender<FlowEvent>,
    state: &PublishedState,
) -> Result<(), AgentError> {
    let mut sock = af_packet::AfPacketSocket::open(
        interface,
        af_packet::RingSettings {
            block_size_bytes: ring_block_size_bytes,
            block_count: ring_block_count,
            retire_timeout_ms: block_retire_timeout_ms,
        },
    )?;
    state
        .capture_ring_bytes
        .store(sock.ring_bytes() as u64, Ordering::Relaxed);
    state
        .capture_ring_blocks
        .store(sock.ring_blocks() as u64, Ordering::Relaxed);
    state
        .capture_block_size_bytes
        .store(sock.block_size_bytes() as u64, Ordering::Relaxed);
    let mut last_statistics = Instant::now();
    loop {
        let mut packets_seen = 0u64;
        let mut packets_parsed = 0u64;
        let mut packets_unparsed = 0u64;
        let poll_result = sock.poll_block(|packet, timestamp_nanos| {
            packets_seen += 1;
            if let Some(mut event) = parse_packet(linktype::ETHERNET, packet) {
                packets_parsed += 1;
                event.ts_nanos = timestamp_nanos;
                if event.bytes == 0 {
                    event.bytes = packet.len() as u32;
                }
                offer_event(tx, event, state)
            } else {
                packets_unparsed += 1;
                true
            }
        });
        if packets_seen != 0 {
            state
                .packets_seen
                .fetch_add(packets_seen, Ordering::Relaxed);
            state
                .packets_parsed
                .fetch_add(packets_parsed, Ordering::Relaxed);
            state
                .packets_unparsed
                .fetch_add(packets_unparsed, Ordering::Relaxed);
        }
        let keep_running = match poll_result {
            Ok(Some(keep_running)) => keep_running,
            Ok(None) => true,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(AgentError::Source(format!(
                    "TPACKET_V3 receive on {interface}: {e}"
                )))
            }
        };
        if last_statistics.elapsed() >= AF_PACKET_STATS_INTERVAL {
            record_packet_statistics(&sock, state, interface)?;
            last_statistics = Instant::now();
        }
        if !keep_running {
            return Ok(());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn ebpf_loop(
    interface: &str,
    _object_path: &std::path::Path,
    _ring_buffer_bytes: u32,
    _tx: &SyncSender<FlowEvent>,
    _state: &PublishedState,
) -> Result<(), AgentError> {
    Err(AgentError::Source(format!(
        "ebpf source ({interface}) is only supported on Linux"
    )))
}

#[cfg(target_os = "linux")]
fn record_packet_statistics(
    sock: &af_packet::AfPacketSocket,
    state: &PublishedState,
    interface: &str,
) -> Result<(), AgentError> {
    let stats = sock
        .statistics()
        .map_err(|e| AgentError::Source(format!("PACKET_STATISTICS on {interface}: {e}")))?;
    state
        .kernel_packets
        .fetch_add(stats.packets as u64, Ordering::Relaxed);
    state
        .kernel_dropped_packets
        .fetch_add(stats.drops as u64, Ordering::Relaxed);
    state
        .kernel_queue_freezes
        .fetch_add(stats.queue_freezes as u64, Ordering::Relaxed);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn af_packet_loop(
    interface: &str,
    _ring_block_size_bytes: u32,
    _ring_block_count: u32,
    _block_retire_timeout_ms: u32,
    _tx: &SyncSender<FlowEvent>,
    _state: &PublishedState,
) -> Result<(), AgentError> {
    Err(AgentError::Source(format!(
        "af_packet source ({interface}) is only supported on Linux"
    )))
}
