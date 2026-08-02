//! Queue-local runtime for kernel-partitioned AF_PACKET fan-out lanes.
//!
//! Each capture lane has one bounded single-producer event queue and one
//! permanently owning `QueryEngine` thread. A low-frequency two-phase barrier
//! pauses workers between batches, advances every engine to the same observed
//! event-time watermark, and extracts mergeable states. No packet traverses a
//! shared receiver or coordinator.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flowsketch_core::hash::HashSpec;
use flowsketch_core::{FlowEvent, SketchError};
use flowsketch_planner::Plan;
use flowsketch_runtime::{QueryEngine, QueryWindowState, WindowState};

use crate::state::PublishedState;
use crate::AgentError;

const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct LaneEventSender {
    pub(crate) lane: usize,
    pub(crate) tx: SyncSender<FlowEvent>,
}

enum WorkerControl {
    Pause(Sender<PauseAck>),
    Checkpoint {
        watermark: Option<u64>,
        include_current: bool,
        finish: bool,
        reply: Sender<Result<WorkerReport, String>>,
    },
    Shutdown,
}

struct PauseAck {
    lane: usize,
    max_timestamp_nanos: Option<u64>,
}

struct WorkerReport {
    lane: usize,
    completed: Vec<QueryWindowState>,
    current: Vec<QueryWindowState>,
    sketch_memory_bytes: usize,
    late_events: u64,
}

struct WorkerFailure {
    lane: usize,
    detail: String,
}

pub(crate) struct DirectRuntime {
    controls: Vec<Sender<WorkerControl>>,
    workers: Vec<JoinHandle<()>>,
    failures: Receiver<WorkerFailure>,
    drained: Receiver<PauseAck>,
    plans: BTreeMap<String, Plan>,
    published: Arc<PublishedState>,
}

struct DirectRuntimeOptions<'a> {
    lane_count: usize,
    batch_size: usize,
    worker_cpus: Option<&'a [usize]>,
    total_channel_capacity: usize,
    initial_watermark_nanos: u64,
}

impl DirectRuntime {
    pub(crate) fn new(
        plans: &[Plan],
        hash: HashSpec,
        lane_count: usize,
        batch_size: usize,
        worker_cpus: Option<&[usize]>,
        total_channel_capacity: usize,
        published: Arc<PublishedState>,
    ) -> Result<(Self, Vec<LaneEventSender>), AgentError> {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                AgentError::Source(format!("system clock is before epoch: {error}"))
            })?;
        let initial_watermark_nanos = u64::try_from(since_epoch.as_nanos()).unwrap_or(u64::MAX);
        Self::new_with_options(
            plans,
            hash,
            published,
            DirectRuntimeOptions {
                lane_count,
                batch_size,
                worker_cpus,
                total_channel_capacity,
                initial_watermark_nanos,
            },
        )
    }

    fn new_with_options(
        plans: &[Plan],
        hash: HashSpec,
        published: Arc<PublishedState>,
        options: DirectRuntimeOptions<'_>,
    ) -> Result<(Self, Vec<LaneEventSender>), AgentError> {
        let DirectRuntimeOptions {
            lane_count,
            batch_size,
            worker_cpus,
            total_channel_capacity,
            initial_watermark_nanos,
        } = options;
        if lane_count == 0 || total_channel_capacity < lane_count {
            return Err(AgentError::Config(format!(
                "queue-local runtime needs at least one event slot per lane (lanes={lane_count}, capacity={total_channel_capacity})"
            )));
        }
        if batch_size == 0 {
            return Err(AgentError::Config(
                "queue-local runtime batch size must be greater than zero".into(),
            ));
        }
        if let Some(cpus) = worker_cpus {
            if cpus.len() != lane_count {
                return Err(AgentError::Config(format!(
                    "runtime CPU affinity lists {} CPU(s) for {lane_count} shard worker(s)",
                    cpus.len()
                )));
            }
        }

        // Construct every sketch engine before starting threads so invalid
        // plans fail without leaving a partially initialized runtime.
        let mut engines = (0..lane_count)
            .map(|_| QueryEngine::new(plans.to_vec(), hash))
            .collect::<Result<Vec<_>, _>>()?;
        // AF_PACKET timestamps are realtime nanoseconds. Seeding every lane
        // at the same pre-capture boundary preserves an honest partial first
        // window while ensuring idle and late-starting lanes remain mergeable.
        for engine in &mut engines {
            engine.advance_to(initial_watermark_nanos)?;
        }

        let base_capacity = total_channel_capacity / lane_count;
        let extra_slots = total_channel_capacity % lane_count;
        let capacities: Vec<usize> = (0..lane_count)
            .map(|lane| base_capacity + usize::from(lane < extra_slots))
            .collect();
        published.configure_queue_local_channels(&capacities);

        let (failure_tx, failure_rx) = mpsc::channel();
        let (drained_tx, drained_rx) = mpsc::channel();
        let mut controls = Vec::with_capacity(lane_count);
        let mut workers = Vec::with_capacity(lane_count);
        let mut event_senders = Vec::with_capacity(lane_count);

        for (lane, (engine, capacity)) in engines.into_iter().zip(capacities).enumerate() {
            let (event_tx, event_rx) = mpsc::sync_channel(capacity);
            let (control_tx, control_rx) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let worker_state = Arc::clone(&published);
            let worker_failure_tx = failure_tx.clone();
            let worker_drained_tx = drained_tx.clone();
            let cpu = worker_cpus.and_then(|cpus| cpus.get(lane)).copied();
            let spawn = std::thread::Builder::new()
                .name(format!("fs-runtime-{lane}"))
                .spawn(move || {
                    let ready_result = pin_runtime_worker(cpu, lane).map_err(|error| match cpu {
                        Some(cpu) => {
                            format!("cannot pin runtime worker {lane} to CPU {cpu}: {error}")
                        }
                        None => format!("cannot start runtime worker {lane}: {error}"),
                    });
                    let ready_failed = ready_result.is_err();
                    if ready_tx.send(ready_result).is_err() || ready_failed {
                        return;
                    }

                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        worker_loop(
                            lane,
                            engine,
                            event_rx,
                            control_rx,
                            batch_size,
                            &worker_state,
                            worker_drained_tx,
                        )
                    }));
                    let detail = match result {
                        Ok(Ok(())) => return,
                        Ok(Err(error)) => error,
                        Err(_) => format!("runtime worker {lane} panicked"),
                    };
                    worker_state.ready.store(false, Ordering::Release);
                    *worker_state.source_error.lock().unwrap() = Some(detail.clone());
                    let _ = worker_failure_tx.send(WorkerFailure { lane, detail });
                });
            let worker = match spawn {
                Ok(worker) => worker,
                Err(error) => {
                    shutdown_workers(&controls, &mut workers);
                    return Err(AgentError::Io(error));
                }
            };

            controls.push(control_tx);
            workers.push(worker);
            event_senders.push(LaneEventSender { lane, tx: event_tx });

            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(detail)) => {
                    shutdown_workers(&controls, &mut workers);
                    return Err(AgentError::Source(detail));
                }
                Err(_) => {
                    shutdown_workers(&controls, &mut workers);
                    return Err(AgentError::Source(format!(
                        "runtime worker {lane} ended before reporting readiness"
                    )));
                }
            }
        }
        drop(failure_tx);
        drop(drained_tx);

        let plans = plans
            .iter()
            .cloned()
            .map(|plan| (plan.query.name.clone(), plan))
            .collect();
        Ok((
            DirectRuntime {
                controls,
                workers,
                failures: failure_rx,
                drained: drained_rx,
                plans,
                published,
            },
            event_senders,
        ))
    }

    pub(crate) fn checkpoint(&mut self, finish: bool) -> Result<(), AgentError> {
        self.check_failure()?;
        if finish {
            let mut drained = Vec::with_capacity(self.controls.len());
            for _ in 0..self.controls.len() {
                drained.push(self.recv_worker(&self.drained)?);
            }
            drained.sort_by_key(|ack| ack.lane);
            for (expected, ack) in drained.iter().enumerate() {
                if ack.lane != expected {
                    return Err(AgentError::Source(format!(
                        "queue-local final drain received duplicate or missing lane {}; expected lane {expected}",
                        ack.lane
                    )));
                }
            }
        }
        let (pause_tx, pause_rx) = mpsc::channel();
        for control in &self.controls {
            control
                .send(WorkerControl::Pause(pause_tx.clone()))
                .map_err(|_| self.worker_disconnect_error())?;
        }
        drop(pause_tx);

        let mut acknowledgements = Vec::with_capacity(self.controls.len());
        for _ in 0..self.controls.len() {
            acknowledgements.push(self.recv_worker(&pause_rx)?);
        }
        acknowledgements.sort_by_key(|ack| ack.lane);
        for (expected, ack) in acknowledgements.iter().enumerate() {
            if ack.lane != expected {
                return Err(AgentError::Source(format!(
                    "queue-local publication received duplicate or missing lane {}; expected lane {expected}",
                    ack.lane
                )));
            }
        }
        let watermark = acknowledgements
            .iter()
            .filter_map(|ack| ack.max_timestamp_nanos)
            .max();
        let include_current = self.published.snapshot_export_due(finish);

        let (report_tx, report_rx) = mpsc::channel();
        for control in &self.controls {
            control
                .send(WorkerControl::Checkpoint {
                    watermark,
                    include_current,
                    finish,
                    reply: report_tx.clone(),
                })
                .map_err(|_| self.worker_disconnect_error())?;
        }
        drop(report_tx);

        let mut reports = Vec::with_capacity(self.controls.len());
        for _ in 0..self.controls.len() {
            let report = self.recv_worker(&report_rx)?.map_err(AgentError::Source)?;
            reports.push(report);
        }
        reports.sort_by_key(|report| report.lane);
        for (expected, report) in reports.iter().enumerate() {
            if report.lane != expected {
                return Err(AgentError::Source(format!(
                    "queue-local checkpoint received duplicate or missing lane {}; expected lane {expected}",
                    report.lane
                )));
            }
        }

        self.publish_reports(reports, include_current)?;
        if finish {
            for worker in self.workers.drain(..) {
                if worker.join().is_err() {
                    return Err(AgentError::Source(
                        "queue-local runtime worker panicked during shutdown".into(),
                    ));
                }
            }
            self.controls.clear();
        }
        self.check_failure()
    }

    fn publish_reports(
        &self,
        reports: Vec<WorkerReport>,
        include_current: bool,
    ) -> Result<(), AgentError> {
        let mut completed = BTreeMap::new();
        let mut current = BTreeMap::new();
        let mut current_bounds: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut memory_bytes = 0usize;
        let mut late_events = 0u64;

        for report in reports {
            memory_bytes = memory_bytes.saturating_add(report.sketch_memory_bytes);
            late_events = late_events.saturating_add(report.late_events);
            merge_windows(&mut completed, report.completed)?;
            if include_current {
                for window in &report.current {
                    let bounds = (
                        window.state.window_start_nanos(),
                        window.state.window_end_nanos(),
                    );
                    match current_bounds.get(&window.query_name) {
                        Some(existing) if *existing != bounds => {
                            return Err(AgentError::Engine(SketchError::IncompatibleMerge(
                                format!(
                                    "queue-local query {:?} has unaligned current windows {:?} and {bounds:?}",
                                    window.query_name, existing
                                ),
                            )));
                        }
                        None => {
                            current_bounds.insert(window.query_name.clone(), bounds);
                        }
                        Some(_) => {}
                    }
                }
                merge_windows(&mut current, report.current)?;
            }
        }

        let mut estimates = Vec::new();
        for ((query, _, _), state) in completed {
            let plan = self.plans.get(&query).ok_or_else(|| {
                AgentError::Engine(SketchError::InvalidParam(format!(
                    "queue-local runtime produced unknown query {query:?}"
                )))
            })?;
            estimates.extend(state.estimates(plan));
        }
        let snapshots = if include_current {
            let mut snapshots = Vec::new();
            for ((query, _, _), state) in current {
                snapshots.extend(state.snapshot_exports(&query));
            }
            Some(snapshots)
        } else {
            None
        };

        self.published
            .publish_queue_local(estimates, memory_bytes, late_events, snapshots);
        Ok(())
    }

    fn check_failure(&self) -> Result<(), AgentError> {
        match self.failures.try_recv() {
            Ok(failure) => Err(AgentError::Source(format!(
                "runtime lane {} failed: {}",
                failure.lane, failure.detail
            ))),
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => Ok(()),
        }
    }

    fn recv_worker<T>(&self, receiver: &Receiver<T>) -> Result<T, AgentError> {
        loop {
            match receiver.recv_timeout(CONTROL_POLL_INTERVAL) {
                Ok(value) => return Ok(value),
                Err(mpsc::RecvTimeoutError::Timeout) => self.check_failure()?,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(self.worker_disconnect_error());
                }
            }
        }
    }

    fn worker_disconnect_error(&self) -> AgentError {
        match self.failures.try_recv() {
            Ok(failure) => AgentError::Source(format!(
                "runtime lane {} failed: {}",
                failure.lane, failure.detail
            )),
            Err(_) => AgentError::Source(
                "queue-local runtime worker disconnected during publication".into(),
            ),
        }
    }
}

impl Drop for DirectRuntime {
    fn drop(&mut self) {
        shutdown_workers(&self.controls, &mut self.workers);
    }
}

fn shutdown_workers(controls: &[Sender<WorkerControl>], workers: &mut Vec<JoinHandle<()>>) {
    for control in controls {
        let _ = control.send(WorkerControl::Shutdown);
    }
    for worker in workers.drain(..) {
        let _ = worker.join();
    }
}

fn worker_loop(
    lane: usize,
    mut engine: QueryEngine,
    event_rx: Receiver<FlowEvent>,
    control_rx: Receiver<WorkerControl>,
    batch_size: usize,
    state: &PublishedState,
    drained: Sender<PauseAck>,
) -> Result<(), String> {
    let mut max_timestamp_nanos = None::<u64>;
    let mut data_open = true;
    loop {
        let control = match control_rx.try_recv() {
            Ok(control) => Some(control),
            Err(TryRecvError::Disconnected) => return Ok(()),
            Err(TryRecvError::Empty) => None,
        };
        if let Some(control) = control {
            if handle_control(control, lane, &mut engine, &control_rx, max_timestamp_nanos)? {
                return Ok(());
            }
            continue;
        }

        if !data_open {
            let control = control_rx
                .recv()
                .map_err(|_| format!("runtime worker {lane} control channel disconnected"))?;
            if handle_control(control, lane, &mut engine, &control_rx, max_timestamp_nanos)? {
                return Ok(());
            }
            continue;
        }

        let first = match event_rx.recv_timeout(CONTROL_POLL_INTERVAL) {
            Ok(event) => event,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                data_open = false;
                drained
                    .send(PauseAck {
                        lane,
                        max_timestamp_nanos,
                    })
                    .map_err(|_| format!("runtime worker {lane} cannot report its final drain"))?;
                continue;
            }
        };

        let mut processed = 0u64;
        let mut next_event = Some(first);
        while processed < batch_size as u64 {
            let Some(event) = next_event.take() else {
                break;
            };
            engine.process(&event).map_err(|error| {
                format!("runtime worker {lane} could not process event: {error}")
            })?;
            max_timestamp_nanos = Some(
                max_timestamp_nanos.map_or(event.ts_nanos, |current| current.max(event.ts_nanos)),
            );
            processed += 1;
            if processed == batch_size as u64 {
                break;
            }

            next_event = match event_rx.try_recv() {
                Ok(event) => Some(event),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => {
                    data_open = false;
                    drained
                        .send(PauseAck {
                            lane,
                            max_timestamp_nanos,
                        })
                        .map_err(|_| {
                            format!("runtime worker {lane} cannot report its final drain")
                        })?;
                    None
                }
            };
        }
        state
            .events_processed
            .fetch_add(processed, Ordering::Relaxed);
        state.record_capture_lane_events_processed(lane, processed);
        state.runtime_batches.fetch_add(1, Ordering::Relaxed);
    }
}

fn handle_control(
    control: WorkerControl,
    lane: usize,
    engine: &mut QueryEngine,
    control_rx: &Receiver<WorkerControl>,
    max_timestamp_nanos: Option<u64>,
) -> Result<bool, String> {
    match control {
        WorkerControl::Shutdown => Ok(true),
        WorkerControl::Checkpoint { .. } => Err(format!(
            "runtime worker {lane} received a checkpoint before pause"
        )),
        WorkerControl::Pause(ack) => {
            ack.send(PauseAck {
                lane,
                max_timestamp_nanos,
            })
            .map_err(|_| format!("runtime worker {lane} cannot acknowledge pause"))?;
            match control_rx.recv() {
                Ok(WorkerControl::Checkpoint {
                    watermark,
                    include_current,
                    finish,
                    reply,
                }) => {
                    let result = build_report(lane, engine, watermark, include_current, finish);
                    reply
                        .send(result)
                        .map_err(|_| format!("runtime worker {lane} cannot return checkpoint"))?;
                    Ok(finish)
                }
                Ok(WorkerControl::Shutdown) => Ok(true),
                Ok(WorkerControl::Pause(_)) => {
                    Err(format!("runtime worker {lane} received two pause commands"))
                }
                Err(_) => Ok(true),
            }
        }
    }
}

fn build_report(
    lane: usize,
    engine: &mut QueryEngine,
    watermark: Option<u64>,
    include_current: bool,
    finish: bool,
) -> Result<WorkerReport, String> {
    if let Some(watermark) = watermark {
        engine
            .advance_to(watermark)
            .map_err(|error| format!("runtime worker {lane} cannot advance watermark: {error}"))?;
    }
    if finish {
        engine
            .finish()
            .map_err(|error| format!("runtime worker {lane} cannot finish: {error}"))?;
    }
    let completed = engine.take_window_states();
    let current = if include_current {
        engine.current_window_states().map_err(|error| {
            format!("runtime worker {lane} cannot checkpoint current windows: {error}")
        })?
    } else {
        Vec::new()
    };
    Ok(WorkerReport {
        lane,
        completed,
        current,
        sketch_memory_bytes: engine.sketch_memory_bytes(),
        late_events: engine.late_events(),
    })
}

fn merge_windows(
    merged: &mut BTreeMap<(String, u64, u64), WindowState>,
    windows: Vec<QueryWindowState>,
) -> Result<(), AgentError> {
    for window in windows {
        let key = (
            window.query_name,
            window.state.window_start_nanos(),
            window.state.window_end_nanos(),
        );
        match merged.get_mut(&key) {
            Some(state) => state.merge_from(&window.state)?,
            None => {
                merged.insert(key, window.state);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pin_runtime_worker(cpu: Option<usize>, _lane: usize) -> std::io::Result<()> {
    match cpu {
        Some(cpu) => crate::affinity::pin_current_thread(cpu),
        None => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_runtime_worker(cpu: Option<usize>, lane: usize) -> std::io::Result<()> {
    if let Some(cpu) = cpu {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("cannot pin runtime worker {lane} to CPU {cpu} outside Linux"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    use flowsketch_ir::parse_query_yaml;
    use flowsketch_planner::plan;

    fn test_plan(hash: &HashSpec) -> Plan {
        let query = parse_query_yaml(
            "name: lane-count\n\
             window: {size: 60s, slide: 10s}\n\
             groupBy: [src.ip]\n\
             measure: {type: count}\n",
        )
        .unwrap();
        plan(query, hash).unwrap()
    }

    fn event(timestamp_seconds: u64) -> FlowEvent {
        FlowEvent {
            ts_nanos: timestamp_seconds * 1_000_000_000,
            src_ip: "10.0.0.7".parse::<IpAddr>().unwrap(),
            dst_ip: "10.0.0.8".parse::<IpAddr>().unwrap(),
            src_port: 40_000,
            dst_port: 443,
            protocol: 6,
            bytes: 100,
            ..FlowEvent::default()
        }
    }

    fn wait_for_events(state: &PublishedState, expected: u64) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while state.events_processed.load(Ordering::Acquire) < expected {
            assert!(
                Instant::now() < deadline,
                "runtime did not process {expected} events before the test deadline"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn checkpoints_merge_lanes_and_final_checkpoint_drains_every_queue() {
        let hash = HashSpec::new(7);
        let plan = test_plan(&hash);
        let state = Arc::new(PublishedState::new(std::slice::from_ref(&plan), 2, None, 2));
        state.enable_snapshot_export(Duration::from_secs(60));
        let (mut runtime, senders) = DirectRuntime::new_with_options(
            std::slice::from_ref(&plan),
            hash,
            Arc::clone(&state),
            DirectRuntimeOptions {
                lane_count: 2,
                batch_size: 16,
                worker_cpus: None,
                total_channel_capacity: 7,
                initial_watermark_nanos: 0,
            },
        )
        .unwrap();

        senders[0].tx.send(event(1)).unwrap();
        senders[1].tx.send(event(1)).unwrap();
        wait_for_events(&state, 2);

        // Advancing only one lane still closes the same global window on
        // both workers at the publication barrier.
        senders[0].tx.send(event(12)).unwrap();
        wait_for_events(&state, 3);
        runtime.checkpoint(false).unwrap();
        let first = state.latest_estimates();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].window_end_nanos, 10_000_000_000);
        assert_eq!(first[0].estimate, 2.0);
        assert!(!state.latest_snapshots().is_empty());

        // The last sender closes after an event is queued. Final checkpoint
        // must wait for that event to be consumed before workers finish.
        senders[1].tx.send(event(12)).unwrap();
        drop(senders);
        runtime.checkpoint(true).unwrap();

        assert_eq!(state.events_processed.load(Ordering::Acquire), 4);
        assert_eq!(state.late_events.load(Ordering::Acquire), 0);
        let final_estimates = state.latest_estimates();
        assert_eq!(final_estimates.len(), 1);
        assert_eq!(final_estimates[0].window_end_nanos, 20_000_000_000);
        assert_eq!(final_estimates[0].estimate, 4.0);

        let metrics = state.render_health_metrics();
        for expected in [
            "flowsketch_agent_af_packet_queue_local_handoff 1\n",
            "flowsketch_agent_af_packet_lane_channel_capacity{lane=\"0\"} 4\n",
            "flowsketch_agent_af_packet_lane_channel_capacity{lane=\"1\"} 3\n",
            "flowsketch_agent_af_packet_lane_events_processed_total{lane=\"0\"} 2\n",
            "flowsketch_agent_af_packet_lane_events_processed_total{lane=\"1\"} 2\n",
        ] {
            assert!(metrics.contains(expected), "missing {expected:?}");
        }
    }

    #[test]
    fn rejects_zero_batch_size_before_starting_workers() {
        let hash = HashSpec::new(7);
        let plan = test_plan(&hash);
        let state = Arc::new(PublishedState::new(std::slice::from_ref(&plan), 2, None, 2));
        let error = DirectRuntime::new_with_options(
            &[plan],
            hash,
            state,
            DirectRuntimeOptions {
                lane_count: 2,
                batch_size: 0,
                worker_cpus: None,
                total_channel_capacity: 8,
                initial_watermark_nanos: 0,
            },
        )
        .err()
        .expect("zero batch size must be rejected");
        assert!(error
            .to_string()
            .contains("batch size must be greater than zero"));
    }

    #[test]
    fn full_batches_do_not_dequeue_an_extra_event() {
        let hash = HashSpec::new(7);
        let plan = test_plan(&hash);
        let state = Arc::new(PublishedState::new(std::slice::from_ref(&plan), 1, None, 1));
        let (mut runtime, senders) = DirectRuntime::new_with_options(
            &[plan],
            hash,
            Arc::clone(&state),
            DirectRuntimeOptions {
                lane_count: 1,
                batch_size: 4,
                worker_cpus: None,
                total_channel_capacity: 32,
                initial_watermark_nanos: 0,
            },
        )
        .unwrap();

        for second in 1..=25 {
            senders[0].tx.send(event(second)).unwrap();
        }
        drop(senders);
        runtime.checkpoint(true).unwrap();

        assert_eq!(state.events_processed.load(Ordering::Acquire), 25);
        assert_eq!(state.late_events.load(Ordering::Acquire), 0);
    }

    #[test]
    fn snapshot_barrier_aligns_a_lane_that_starts_late() {
        let hash = HashSpec::new(7);
        let plan = test_plan(&hash);
        let state = Arc::new(PublishedState::new(std::slice::from_ref(&plan), 2, None, 2));
        state.enable_snapshot_export(Duration::from_secs(60));
        let (mut runtime, senders) = DirectRuntime::new_with_options(
            &[plan],
            hash,
            Arc::clone(&state),
            DirectRuntimeOptions {
                lane_count: 2,
                batch_size: 8,
                worker_cpus: None,
                total_channel_capacity: 32,
                initial_watermark_nanos: 0,
            },
        )
        .unwrap();

        senders[0].tx.send(event(1)).unwrap();
        senders[1].tx.send(event(31)).unwrap();
        wait_for_events(&state, 2);
        runtime.checkpoint(false).unwrap();
        assert!(!state.latest_snapshots().is_empty());

        drop(senders);
        runtime.checkpoint(true).unwrap();
        let final_estimate = state
            .latest_estimates()
            .into_iter()
            .find(|estimate| estimate.window_end_nanos == 40_000_000_000)
            .unwrap();
        assert_eq!(final_estimate.window_start_nanos, 0);
        assert_eq!(final_estimate.estimate, 2.0);
    }
}
