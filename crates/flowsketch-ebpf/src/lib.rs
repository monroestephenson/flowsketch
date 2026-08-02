//! Stable eBPF collector event contract plus the Linux tc ingress loader.
//!
//! The kernel program extracts packet metadata into the normalized record
//! below and never modifies traffic. Sketch planning and state remain in
//! userspace. Linux loader code is isolated behind `cfg(target_os = "linux")`
//! so the contract and the rest of the workspace remain portable.

#[cfg(target_os = "linux")]
mod tc;

#[cfg(target_os = "linux")]
pub use tc::{TcCollector, TcCollectorCounters, TcCollectorError};

use flowsketch_core::{Direction, FlowEvent};
use thiserror::Error;

/// Version of the kernel/userspace ring-buffer record below. Increment this
/// whenever field semantics, order, size, or byte order changes.
pub const EBPF_ABI_VERSION: u16 = 1;
pub const EBPF_FLOW_EVENT_SIZE: usize = 56;

/// Stable ELF symbol and map names shared by the C producer and Rust loader.
pub const EBPF_ABI_SYMBOL: &str = "FLOWSKETCH_ABI_VERSION";
pub const EBPF_EVENTS_MAP: &str = "EVENTS";
pub const EBPF_COUNTERS_MAP: &str = "COUNTERS";
pub const EBPF_TC_PROGRAM: &str = "flowsketch_tc";

/// Kernel counter indexes. Keep these synchronized with
/// `bpf/flowsketch_tc.bpf.c`; the conformance smoke validates their identity.
pub mod counter {
    pub const PACKETS: u32 = 0;
    pub const EMITTED: u32 = 1;
    pub const RING_DROPS: u32 = 2;
    pub const PARSE_ERRORS: u32 = 3;
    pub const UNSUPPORTED: u32 = 4;
    pub const COUNT: u32 = 5;
}

/// Wire values used for `EbpfFlowEvent::direction`.
pub mod direction {
    pub const UNKNOWN: u8 = 0;
    pub const INGRESS: u8 = 1;
    pub const EGRESS: u8 = 2;
}

/// Stable native-endian representation of one ring-buffer record.
///
/// The kernel program must convert network-order ports to host order before
/// emission. `ts_nanos` is `bpf_ktime_get_ns()` in the kernel monotonic clock
/// domain, never Unix epoch time; userspace must normalize it before building
/// a `FlowEvent`. Field order deliberately avoids implicit padding; both the C
/// and Rust definitions must remain exactly `EBPF_FLOW_EVENT_SIZE` bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfFlowEvent {
    pub ts_nanos: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub bytes: u32,
    pub interface_index: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_version: u8,
    pub tcp_flags: u8,
    pub direction: u8,
}

const _: [(); EBPF_FLOW_EVENT_SIZE] = [(); std::mem::size_of::<EbpfFlowEvent>()];

impl EbpfFlowEvent {
    /// Decode one record copied from a Linux eBPF ring buffer. Explicit field
    /// reads avoid alignment assumptions when the input is an arbitrary byte
    /// slice owned by the loader.
    pub fn decode_ne(bytes: &[u8]) -> Result<Self, EbpfError> {
        if bytes.len() != EBPF_FLOW_EVENT_SIZE {
            return Err(EbpfError::InvalidRecordSize {
                expected: EBPF_FLOW_EVENT_SIZE,
                actual: bytes.len(),
            });
        }
        let mut src_ip = [0; 16];
        src_ip.copy_from_slice(&bytes[8..24]);
        let mut dst_ip = [0; 16];
        dst_ip.copy_from_slice(&bytes[24..40]);
        Ok(Self {
            ts_nanos: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
            src_ip,
            dst_ip,
            bytes: u32::from_ne_bytes(bytes[40..44].try_into().unwrap()),
            interface_index: u32::from_ne_bytes(bytes[44..48].try_into().unwrap()),
            src_port: u16::from_ne_bytes(bytes[48..50].try_into().unwrap()),
            dst_port: u16::from_ne_bytes(bytes[50..52].try_into().unwrap()),
            protocol: bytes[52],
            ip_version: bytes[53],
            tcp_flags: bytes[54],
            direction: bytes[55],
        })
    }

    /// Encode the canonical record layout. Primarily useful for conformance
    /// fixtures shared by the future kernel and userspace loader tests.
    pub fn encode_ne(self) -> [u8; EBPF_FLOW_EVENT_SIZE] {
        let mut out = [0; EBPF_FLOW_EVENT_SIZE];
        out[0..8].copy_from_slice(&self.ts_nanos.to_ne_bytes());
        out[8..24].copy_from_slice(&self.src_ip);
        out[24..40].copy_from_slice(&self.dst_ip);
        out[40..44].copy_from_slice(&self.bytes.to_ne_bytes());
        out[44..48].copy_from_slice(&self.interface_index.to_ne_bytes());
        out[48..50].copy_from_slice(&self.src_port.to_ne_bytes());
        out[50..52].copy_from_slice(&self.dst_port.to_ne_bytes());
        out[52] = self.protocol;
        out[53] = self.ip_version;
        out[54] = self.tcp_flags;
        out[55] = self.direction;
        out
    }
}

#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("invalid eBPF event record size: expected {expected}, got {actual}")]
    InvalidRecordSize { expected: usize, actual: usize },
    #[error("unsupported IP version {0}")]
    UnsupportedIpVersion(u8),
    #[error("unsupported traffic direction {0}")]
    UnsupportedDirection(u8),
    #[error("cannot sample Linux clocks: {0}")]
    ClockSample(String),
    #[error("eBPF monotonic timestamp {0} cannot be represented as Unix nanoseconds")]
    TimestampOutOfRange(u64),
}

/// Conversion between `bpf_ktime_get_ns()` and Unix epoch nanoseconds. The
/// offset is refreshed by userspace so wall-clock corrections do not leave a
/// long-running collector permanently skewed.
#[derive(Debug, Clone, Copy)]
pub struct KernelClockConverter {
    realtime_minus_monotonic: i128,
}

impl KernelClockConverter {
    pub fn from_samples(monotonic_nanos: u64, realtime_nanos: u64) -> Self {
        Self {
            realtime_minus_monotonic: i128::from(realtime_nanos) - i128::from(monotonic_nanos),
        }
    }

    pub fn to_unix_nanos(self, monotonic_nanos: u64) -> Result<u64, EbpfError> {
        let unix = i128::from(monotonic_nanos) + self.realtime_minus_monotonic;
        u64::try_from(unix).map_err(|_| EbpfError::TimestampOutOfRange(monotonic_nanos))
    }

    #[cfg(target_os = "linux")]
    pub fn sample() -> Result<Self, EbpfError> {
        let before = clock_nanos(libc::CLOCK_MONOTONIC)?;
        let realtime = clock_nanos(libc::CLOCK_REALTIME)?;
        let after = clock_nanos(libc::CLOCK_MONOTONIC)?;
        let midpoint = before.saturating_add(after.saturating_sub(before) / 2);
        Ok(Self::from_samples(midpoint, realtime))
    }
}

#[cfg(target_os = "linux")]
fn clock_nanos(clock: libc::clockid_t) -> Result<u64, EbpfError> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes the provided timespec on success.
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
        return Err(EbpfError::ClockSample(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(EbpfError::ClockSample(format!(
            "clock {clock} returned invalid timespec {}.{:09}",
            value.tv_sec, value.tv_nsec
        )));
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| EbpfError::ClockSample("negative clock seconds".into()))?;
    let nanos = u64::try_from(value.tv_nsec)
        .map_err(|_| EbpfError::ClockSample("negative clock nanoseconds".into()))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or_else(|| EbpfError::ClockSample("clock nanoseconds overflow u64".into()))
}

impl EbpfFlowEvent {
    /// Validate this kernel record and build a `FlowEvent` with a timestamp
    /// already normalized to Unix epoch nanoseconds.
    pub fn try_into_flow_event(self, unix_ts_nanos: u64) -> Result<FlowEvent, EbpfError> {
        let event = self;

        let src_ip = match event.ip_version {
            4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                event.src_ip[12],
                event.src_ip[13],
                event.src_ip[14],
                event.src_ip[15],
            )),
            6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(event.src_ip)),
            other => return Err(EbpfError::UnsupportedIpVersion(other)),
        };
        let dst_ip = match event.ip_version {
            4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                event.dst_ip[12],
                event.dst_ip[13],
                event.dst_ip[14],
                event.dst_ip[15],
            )),
            6 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(event.dst_ip)),
            other => return Err(EbpfError::UnsupportedIpVersion(other)),
        };
        let direction = match event.direction {
            direction::UNKNOWN => Direction::Unknown,
            direction::INGRESS => Direction::Ingress,
            direction::EGRESS => Direction::Egress,
            other => return Err(EbpfError::UnsupportedDirection(other)),
        };
        Ok(FlowEvent {
            ts_nanos: unix_ts_nanos,
            src_ip,
            dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            bytes: event.bytes,
            packets: 1,
            direction,
            tcp_flags: event.tcp_flags,
            interface_index: event.interface_index,
            ..FlowEvent::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ipv4_event_to_flow_event() {
        let mut src = [0u8; 16];
        src[12..].copy_from_slice(&[10, 0, 0, 1]);
        let mut dst = [0u8; 16];
        dst[12..].copy_from_slice(&[10, 0, 0, 2]);
        let ev = EbpfFlowEvent {
            ts_nanos: 1,
            src_ip: src,
            dst_ip: dst,
            src_port: 1234,
            dst_port: 443,
            bytes: 1500,
            interface_index: 2,
            protocol: 6,
            ip_version: 4,
            tcp_flags: 0x12,
            direction: direction::INGRESS,
        };
        let flow = ev.try_into_flow_event(1_700_000_000_000_000_000).unwrap();
        assert_eq!(flow.src_ip.to_string(), "10.0.0.1");
        assert_eq!(flow.dst_ip.to_string(), "10.0.0.2");
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.interface_index, 2);
        assert_eq!(flow.direction, Direction::Ingress);
        assert_eq!(flow.ts_nanos, 1_700_000_000_000_000_000);
    }

    #[test]
    fn rejects_unknown_ip_version() {
        let ev = EbpfFlowEvent {
            ts_nanos: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            bytes: 0,
            interface_index: 0,
            protocol: 0,
            ip_version: 5,
            tcp_flags: 0,
            direction: direction::UNKNOWN,
        };
        assert!(ev.try_into_flow_event(1).is_err());
    }

    #[test]
    fn monotonic_clock_conversion_produces_epoch_time() {
        let converter =
            KernelClockConverter::from_samples(5_000_000_000, 1_700_000_000_000_000_000);
        assert_eq!(
            converter.to_unix_nanos(6_000_000_000).unwrap(),
            1_700_000_001_000_000_000
        );
        let underflow = KernelClockConverter::from_samples(10, 0);
        assert!(matches!(
            underflow.to_unix_nanos(0),
            Err(EbpfError::TimestampOutOfRange(0))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sampled_clock_conversion_is_contemporary() {
        let converter = KernelClockConverter::sample().unwrap();
        let monotonic = clock_nanos(libc::CLOCK_MONOTONIC).unwrap();
        let converted = converter.to_unix_nanos(monotonic).unwrap();
        let realtime = clock_nanos(libc::CLOCK_REALTIME).unwrap();
        assert!(converted.abs_diff(realtime) < 1_000_000_000);
    }

    #[test]
    fn wire_record_has_stable_layout_and_round_trips() {
        let event = EbpfFlowEvent {
            ts_nanos: 0x0102_0304_0506_0708,
            src_ip: [0x11; 16],
            dst_ip: [0x22; 16],
            bytes: 1500,
            interface_index: 9,
            src_port: 1234,
            dst_port: 443,
            protocol: 6,
            ip_version: 6,
            tcp_flags: 0x12,
            direction: direction::EGRESS,
        };
        assert_eq!(std::mem::size_of::<EbpfFlowEvent>(), EBPF_FLOW_EVENT_SIZE);
        let encoded = event.encode_ne();
        assert_eq!(&encoded[8..24], &[0x11; 16]);
        assert_eq!(&encoded[24..40], &[0x22; 16]);
        assert_eq!(EbpfFlowEvent::decode_ne(&encoded).unwrap(), event);
    }

    #[test]
    fn wire_decoder_rejects_wrong_size_and_direction() {
        for len in 0..=EBPF_FLOW_EVENT_SIZE * 2 {
            if len == EBPF_FLOW_EVENT_SIZE {
                continue;
            }
            assert!(matches!(
                EbpfFlowEvent::decode_ne(&vec![0; len]),
                Err(EbpfError::InvalidRecordSize { .. })
            ));
        }
        let mut encoded = EbpfFlowEvent {
            ts_nanos: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            bytes: 0,
            interface_index: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            ip_version: 4,
            tcp_flags: 0,
            direction: direction::UNKNOWN,
        }
        .encode_ne();
        encoded[55] = 99;
        let event = EbpfFlowEvent::decode_ne(&encoded).unwrap();
        assert!(matches!(
            event.try_into_flow_event(1),
            Err(EbpfError::UnsupportedDirection(99))
        ));
    }
}
