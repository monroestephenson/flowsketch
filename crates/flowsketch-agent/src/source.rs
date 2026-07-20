//! Capture sources: pcap replay, AF_PACKET TPACKET_V3, and Linux tc eBPF.

#[cfg(target_os = "linux")]
mod af_packet;

#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use flowsketch_core::FlowEvent;
use flowsketch_pcap::PcapReader;
#[cfg(target_os = "linux")]
use flowsketch_pcap::{linktype, parse_packet};

use crate::config::{
    default_block_retire_timeout_ms, default_ring_block_count, default_ring_block_size_bytes,
    AfPacketFanoutMode, SourceConfig,
};
#[cfg(target_os = "linux")]
use crate::offer_event;
use crate::state::PublishedState;
use crate::{AgentError, CapturedEvent};

#[cfg(target_os = "linux")]
const AF_PACKET_STATS_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const EBPF_POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const EBPF_STATS_INTERVAL: Duration = Duration::from_secs(1);

struct AfPacketCapture<'a> {
    interface: &'a str,
    ring_block_size_bytes: u32,
    ring_block_count: u32,
    block_retire_timeout_ms: u32,
    fanout_mode: AfPacketFanoutMode,
    fanout_group: u16,
    runtime_shards: usize,
    capture_cpus: &'a [usize],
}

pub(crate) fn capture_loop(
    source: SourceConfig,
    tx: SyncSender<CapturedEvent>,
    state: Arc<PublishedState>,
    capture_cpus: Vec<usize>,
    runtime_shards: usize,
) -> Result<(), AgentError> {
    let kernel_fanout = matches!(
        &source,
        SourceConfig::AfPacket { fanout_mode, .. }
            if *fanout_mode != AfPacketFanoutMode::Single
    );
    if !kernel_fanout {
        pin_capture_lane(capture_cpus.first().copied(), 0)?;
    }
    let result = match source {
        SourceConfig::Pcap { path } => pcap_loop(&path, &tx, &state),
        SourceConfig::AfPacket {
            interface,
            ring_block_size_bytes,
            ring_block_count,
            block_retire_timeout_ms,
            fanout_mode,
            fanout_group,
        } => af_packet_loop(
            AfPacketCapture {
                interface: &interface,
                ring_block_size_bytes,
                ring_block_count,
                block_retire_timeout_ms,
                fanout_mode,
                fanout_group,
                runtime_shards,
                capture_cpus: &capture_cpus,
            },
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
                    AfPacketCapture {
                        interface: &interface,
                        ring_block_size_bytes: default_ring_block_size_bytes(),
                        ring_block_count: default_ring_block_count(),
                        block_retire_timeout_ms: default_block_retire_timeout_ms(),
                        fanout_mode: AfPacketFanoutMode::Single,
                        fanout_group: 0,
                        runtime_shards: 1,
                        capture_cpus: &[],
                    },
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
fn pin_capture_lane(cpu: Option<usize>, lane: usize) -> Result<(), AgentError> {
    let Some(cpu) = cpu else { return Ok(()) };
    crate::affinity::pin_current_thread(cpu).map_err(|error| {
        AgentError::Source(format!(
            "cannot pin capture lane {lane} to CPU {cpu}: {error}"
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn pin_capture_lane(cpu: Option<usize>, _lane: usize) -> Result<(), AgentError> {
    if cpu.is_some() {
        Err(AgentError::Config(
            "CPU affinity is supported only on Linux".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn ebpf_loop(
    interface: &str,
    object_path: &std::path::Path,
    ring_buffer_bytes: u32,
    tx: &SyncSender<CapturedEvent>,
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
                        offer_event(tx, event, state, None)
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
    tx: &SyncSender<CapturedEvent>,
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
        if tx.send(CapturedEvent { event, lane: None }).is_err() {
            break; // engine gone
        }
    }
    Ok(())
}

/// AF_PACKET live capture. Linux only; other platforms return a clear
/// configuration/runtime error.
#[cfg(target_os = "linux")]
fn af_packet_loop(
    options: AfPacketCapture<'_>,
    tx: &SyncSender<CapturedEvent>,
    state: &Arc<PublishedState>,
) -> Result<(), AgentError> {
    let settings = af_packet::RingSettings {
        block_size_bytes: options.ring_block_size_bytes,
        block_count: options.ring_block_count,
        retire_timeout_ms: options.block_retire_timeout_ms,
    };
    if options.fanout_mode != AfPacketFanoutMode::Single {
        return af_packet_fanout_loop(&options, settings, tx, state);
    }

    let sock = af_packet::AfPacketSocket::open(options.interface, settings, None)?;
    record_ring_shape(&sock, 1, state);
    af_packet_socket_loop(sock, options.interface, tx, state, None, None)
}

#[cfg(target_os = "linux")]
fn af_packet_fanout_loop(
    options: &AfPacketCapture<'_>,
    settings: af_packet::RingSettings,
    tx: &SyncSender<CapturedEvent>,
    state: &Arc<PublishedState>,
) -> Result<(), AgentError> {
    let group_id = if options.fanout_group == 0 {
        derived_fanout_group(options.interface)
    } else {
        options.fanout_group
    };
    let socket_mode = match options.fanout_mode {
        AfPacketFanoutMode::Hash => af_packet::FanoutMode::Hash,
        AfPacketFanoutMode::RxQueue => af_packet::FanoutMode::RxQueue,
        AfPacketFanoutMode::Single => unreachable!("single mode dispatched above"),
    };
    let fanout = af_packet::FanoutSettings {
        group_id,
        mode: socket_mode,
    };

    // Join every socket before starting any reader. This makes partial fan-out
    // setup fail closed instead of briefly running with fewer lanes.
    let lanes = options.runtime_shards;
    let mut sockets = Vec::with_capacity(lanes);
    for lane in 0..lanes {
        let socket =
            af_packet::AfPacketSocket::open(options.interface, settings, Some(fanout)).map_err(
                |error| {
                    AgentError::Source(format!(
                        "cannot create AF_PACKET fan-out lane {lane}/{lanes} in group {group_id}: {error}"
                    ))
                },
            )?;
        sockets.push(socket);
    }
    record_ring_shape(&sockets[0], lanes, state);
    eprintln!(
        "AF_PACKET fan-out active: interface={} mode={:?} group={group_id} lanes={lanes}",
        options.interface, options.fanout_mode
    );

    let stop = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(lanes);
    for (lane, socket) in sockets.into_iter().enumerate() {
        let worker_tx = tx.clone();
        let worker_state = Arc::clone(state);
        let worker_stop = Arc::clone(&stop);
        let worker_done = done_tx.clone();
        let worker_interface = options.interface.to_string();
        let cpu = options.capture_cpus.get(lane).copied();
        let spawn = std::thread::Builder::new()
            .name(format!("fs-capture-{lane}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    pin_capture_lane(cpu, lane).and_then(|()| {
                        af_packet_socket_loop(
                            socket,
                            &worker_interface,
                            &worker_tx,
                            &worker_state,
                            Some(lane),
                            Some(&worker_stop),
                        )
                    })
                }))
                .unwrap_or_else(|_| {
                    Err(AgentError::Source(format!(
                        "AF_PACKET fan-out lane {lane} panicked"
                    )))
                });
                worker_stop.store(true, Ordering::Release);
                let _ = worker_done.send((lane, result));
            });
        match spawn {
            Ok(worker) => workers.push((lane, worker)),
            Err(error) => {
                stop.store(true, Ordering::Release);
                for (_, worker) in workers {
                    let _ = worker.join();
                }
                return Err(AgentError::Source(format!(
                    "cannot spawn AF_PACKET fan-out lane {lane}: {error}"
                )));
            }
        }
    }
    drop(done_tx);

    let first = done_rx.recv().map_err(|_| {
        AgentError::Source("all AF_PACKET fan-out lanes ended without reporting status".into())
    })?;
    stop.store(true, Ordering::Release);
    let mut panicked_lane = None;
    for (lane, worker) in workers {
        if worker.join().is_err() && panicked_lane.is_none() {
            panicked_lane = Some(lane);
        }
    }
    let mut outcomes = vec![first];
    outcomes.extend(done_rx.try_iter());
    if let Some((_, error)) = outcomes.into_iter().find(|(_, result)| result.is_err()) {
        return error;
    }
    if let Some(lane) = panicked_lane {
        return Err(AgentError::Source(format!(
            "AF_PACKET fan-out lane {lane} panicked"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn af_packet_socket_loop(
    mut sock: af_packet::AfPacketSocket,
    interface: &str,
    tx: &SyncSender<CapturedEvent>,
    state: &PublishedState,
    lane: Option<usize>,
    stop: Option<&AtomicBool>,
) -> Result<(), AgentError> {
    let mut last_statistics = Instant::now();
    loop {
        if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
            record_packet_statistics(&sock, state, interface, lane)?;
            return Ok(());
        }
        let mut packets_seen = 0u64;
        let mut packets_parsed = 0u64;
        let mut packets_unparsed = 0u64;
        let poll_result = sock.poll_block(|packet, timestamp_nanos| {
            if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
                return false;
            }
            packets_seen += 1;
            if let Some(mut event) = parse_packet(linktype::ETHERNET, packet) {
                packets_parsed += 1;
                event.ts_nanos = timestamp_nanos;
                if event.bytes == 0 {
                    event.bytes = packet.len() as u32;
                }
                offer_event(tx, event, state, lane)
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
            if let Some(lane) = lane {
                state.record_capture_lane_packets(
                    lane,
                    packets_seen,
                    packets_parsed,
                    packets_unparsed,
                );
            }
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
            record_packet_statistics(&sock, state, interface, lane)?;
            last_statistics = Instant::now();
        }
        if !keep_running {
            record_packet_statistics(&sock, state, interface, lane)?;
            return Ok(());
        }
    }
}

#[cfg(target_os = "linux")]
fn record_ring_shape(socket: &af_packet::AfPacketSocket, lanes: usize, state: &PublishedState) {
    state.capture_ring_bytes.store(
        (socket.ring_bytes() as u64).saturating_mul(lanes as u64),
        Ordering::Relaxed,
    );
    state.capture_ring_blocks.store(
        (socket.ring_blocks() as u64).saturating_mul(lanes as u64),
        Ordering::Relaxed,
    );
    state
        .capture_block_size_bytes
        .store(socket.block_size_bytes() as u64, Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
fn derived_fanout_group(interface: &str) -> u16 {
    let mut group = std::process::id() as u16;
    for byte in interface.bytes() {
        group = group.rotate_left(5) ^ u16::from(byte);
    }
    if group == 0 {
        1
    } else {
        group
    }
}

#[cfg(not(target_os = "linux"))]
fn ebpf_loop(
    interface: &str,
    _object_path: &std::path::Path,
    _ring_buffer_bytes: u32,
    _tx: &SyncSender<CapturedEvent>,
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
    lane: Option<usize>,
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
    if let Some(lane) = lane {
        state.record_capture_lane_statistics(
            lane,
            stats.packets as u64,
            stats.drops as u64,
            stats.queue_freezes as u64,
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn af_packet_loop(
    options: AfPacketCapture<'_>,
    _tx: &SyncSender<CapturedEvent>,
    _state: &Arc<PublishedState>,
) -> Result<(), AgentError> {
    let _ = (
        options.ring_block_size_bytes,
        options.ring_block_count,
        options.block_retire_timeout_ms,
        options.fanout_mode,
        options.fanout_group,
        options.runtime_shards,
        options.capture_cpus,
    );
    Err(AgentError::Source(format!(
        "af_packet source ({}) is only supported on Linux",
        options.interface
    )))
}
