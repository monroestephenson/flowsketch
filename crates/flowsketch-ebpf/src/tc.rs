//! Linux tc ingress loader and ring-buffer consumer.

use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::tc::{self, NlOptions, TcAttachOptions};
use aya::programs::{SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader};
use thiserror::Error;

use crate::{
    counter, EbpfError, EbpfFlowEvent, EBPF_ABI_SYMBOL, EBPF_ABI_VERSION, EBPF_COUNTERS_MAP,
    EBPF_EVENTS_MAP, EBPF_TC_PROGRAM,
};

const MIN_RING_BYTES: u32 = 64 * 1024;
const MAX_RING_BYTES: u32 = 1024 * 1024 * 1024;

/// Cumulative counters read from the program's per-CPU array.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcCollectorCounters {
    pub packets: u64,
    pub emitted: u64,
    pub ring_drops: u64,
    pub parse_errors: u64,
    pub unsupported: u64,
}

impl TcCollectorCounters {
    /// Every tc invocation must be classified into exactly one terminal
    /// bucket. A false result is a producer or ABI accounting defect.
    pub fn is_consistent(self) -> bool {
        self.emitted
            .checked_add(self.ring_drops)
            .and_then(|total| total.checked_add(self.parse_errors))
            .and_then(|total| total.checked_add(self.unsupported))
            == Some(self.packets)
    }
}

#[derive(Debug, Error)]
pub enum TcCollectorError {
    #[error("invalid eBPF ring size {0}: expected a power of two between {MIN_RING_BYTES} and {MAX_RING_BYTES} bytes")]
    InvalidRingSize(u32),
    #[error("cannot load eBPF object {path}: {detail}")]
    Load { path: PathBuf, detail: String },
    #[error("eBPF object is missing required program {0}")]
    MissingProgram(&'static str),
    #[error("eBPF object is missing required map {0}")]
    MissingMap(&'static str),
    #[error("cannot use eBPF map {name}: {detail}")]
    Map { name: &'static str, detail: String },
    #[error("cannot load tc program into the kernel verifier: {0}")]
    Verifier(String),
    #[error("cannot attach tc ingress program to {interface}: {detail}")]
    Attach { interface: String, detail: String },
    #[error("cannot poll eBPF ring buffer: {0}")]
    Poll(#[source] io::Error),
    #[error("cannot read eBPF counter {index}: {detail}")]
    Counter { index: u32, detail: String },
    #[error("eBPF counter sum overflow at index {0}")]
    CounterOverflow(u32),
    #[error(transparent)]
    Contract(#[from] EbpfError),
}

/// An attached tc ingress program and its owned userspace map handles.
/// Dropping this value closes the Aya link, which detaches the program.
pub struct TcCollector {
    // Drop the program/link before unmapping the userspace ring consumer.
    _ebpf: Ebpf,
    events: RingBuf<MapData>,
    counters: PerCpuArray<MapData, u64>,
}

impl TcCollector {
    /// Load, verifier-check, and attach the collector. On modern kernels Aya
    /// uses TCX; if that is unavailable, this creates/reuses `clsact` and
    /// retries through the legacy tc netlink attachment.
    pub fn attach(
        interface: &str,
        object_path: &Path,
        ring_buffer_bytes: u32,
    ) -> Result<Self, TcCollectorError> {
        if !(MIN_RING_BYTES..=MAX_RING_BYTES).contains(&ring_buffer_bytes)
            || !ring_buffer_bytes.is_power_of_two()
        {
            return Err(TcCollectorError::InvalidRingSize(ring_buffer_bytes));
        }

        let abi_version = EBPF_ABI_VERSION;
        let mut loader = EbpfLoader::new();
        loader
            .set_max_entries(EBPF_EVENTS_MAP, ring_buffer_bytes)
            .set_global(EBPF_ABI_SYMBOL, &abi_version, true);
        let mut ebpf = loader
            .load_file(object_path)
            .map_err(|error| TcCollectorError::Load {
                path: object_path.to_path_buf(),
                detail: error.to_string(),
            })?;

        {
            let program = ebpf
                .program_mut(EBPF_TC_PROGRAM)
                .ok_or(TcCollectorError::MissingProgram(EBPF_TC_PROGRAM))?;
            let program: &mut SchedClassifier =
                program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        TcCollectorError::Verifier(error.to_string())
                    })?;
            program
                .load()
                .map_err(|error| TcCollectorError::Verifier(error.to_string()))?;

            if let Err(tcx_error) = program.attach(interface, TcAttachType::Ingress) {
                let qdisc_result = tc::qdisc_add_clsact(interface);
                if let Err(error) = &qdisc_result {
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(TcCollectorError::Attach {
                            interface: interface.to_string(),
                            detail: format!(
                                "TCX/initial attach failed ({tcx_error}); cannot create clsact qdisc ({error})"
                            ),
                        });
                    }
                }
                program
                    .attach_with_options(
                        interface,
                        TcAttachType::Ingress,
                        TcAttachOptions::Netlink(NlOptions::default()),
                    )
                    .map_err(|legacy_error| TcCollectorError::Attach {
                        interface: interface.to_string(),
                        detail: format!(
                            "TCX/initial attach failed ({tcx_error}); legacy tc attach failed ({legacy_error})"
                        ),
                    })?;
            }
        }

        let events_map = ebpf
            .take_map(EBPF_EVENTS_MAP)
            .ok_or(TcCollectorError::MissingMap(EBPF_EVENTS_MAP))?;
        let events = RingBuf::try_from(events_map).map_err(|error| TcCollectorError::Map {
            name: EBPF_EVENTS_MAP,
            detail: error.to_string(),
        })?;
        let counters_map = ebpf
            .take_map(EBPF_COUNTERS_MAP)
            .ok_or(TcCollectorError::MissingMap(EBPF_COUNTERS_MAP))?;
        let counters =
            PerCpuArray::try_from(counters_map).map_err(|error| TcCollectorError::Map {
                name: EBPF_COUNTERS_MAP,
                detail: error.to_string(),
            })?;
        if counters.len() != counter::COUNT {
            return Err(TcCollectorError::Map {
                name: EBPF_COUNTERS_MAP,
                detail: format!(
                    "expected {} entries for ABI v{}, got {}",
                    counter::COUNT,
                    EBPF_ABI_VERSION,
                    counters.len()
                ),
            });
        }

        Ok(Self {
            _ebpf: ebpf,
            events,
            counters,
        })
    }

    /// Wait for records, decode the stable ABI, and invoke `handle` without
    /// allocating. Returning false from the callback stops capture cleanly.
    pub fn poll(
        &mut self,
        timeout: Duration,
        mut handle: impl FnMut(EbpfFlowEvent) -> bool,
    ) -> Result<bool, TcCollectorError> {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: self.events.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: descriptor points to one initialized pollfd for the
            // duration of the call; Aya owns and keeps the map fd open.
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if result >= 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(TcCollectorError::Poll(error));
            }
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(TcCollectorError::Poll(io::Error::other(format!(
                "ring map fd returned poll events 0x{:x}",
                descriptor.revents
            ))));
        }

        while let Some(record) = self.events.next() {
            let event = EbpfFlowEvent::decode_ne(&record)?;
            if !handle(event) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn counters(&self) -> Result<TcCollectorCounters, TcCollectorError> {
        Ok(TcCollectorCounters {
            packets: self.counter_sum(counter::PACKETS)?,
            emitted: self.counter_sum(counter::EMITTED)?,
            ring_drops: self.counter_sum(counter::RING_DROPS)?,
            parse_errors: self.counter_sum(counter::PARSE_ERRORS)?,
            unsupported: self.counter_sum(counter::UNSUPPORTED)?,
        })
    }

    fn counter_sum(&self, index: u32) -> Result<u64, TcCollectorError> {
        let values = self
            .counters
            .get(&index, 0)
            .map_err(|error| TcCollectorError::Counter {
                index,
                detail: error.to_string(),
            })?;
        values.iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or(TcCollectorError::CounterOverflow(index))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_identity_detects_missing_packets() {
        let valid = TcCollectorCounters {
            packets: 10,
            emitted: 7,
            ring_drops: 1,
            parse_errors: 1,
            unsupported: 1,
        };
        assert!(valid.is_consistent());
        assert!(!TcCollectorCounters {
            packets: 11,
            ..valid
        }
        .is_consistent());
        assert!(!TcCollectorCounters {
            packets: u64::MAX,
            emitted: u64::MAX,
            ring_drops: 1,
            ..TcCollectorCounters::default()
        }
        .is_consistent());
    }
}
