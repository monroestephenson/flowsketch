//! Stable eBPF collector event contract.
//!
//! This crate intentionally does not claim to load a kernel program yet.
//! It defines the userspace/kernel contract that a future tc/XDP backend
//! must satisfy: extract packet metadata into the same normalized event
//! shape as the pcap and AF_PACKET sources, then feed the existing runtime.
//! The sketch planner and sketch state stay in userspace.

use flowsketch_core::{Direction, FlowEvent};
use thiserror::Error;

/// Version of the kernel/userspace ring-buffer record below. Increment this
/// whenever field semantics, order, size, or byte order changes.
pub const EBPF_ABI_VERSION: u16 = 1;
pub const EBPF_FLOW_EVENT_SIZE: usize = 56;

/// Wire values used for `EbpfFlowEvent::direction`.
pub mod direction {
    pub const UNKNOWN: u8 = 0;
    pub const INGRESS: u8 = 1;
    pub const EGRESS: u8 = 2;
}

/// Stable native-endian representation of one ring-buffer record.
///
/// The kernel program must convert network-order ports to host order before
/// emission. Field order deliberately avoids implicit padding; both the C and
/// Rust definitions must remain exactly `EBPF_FLOW_EVENT_SIZE` bytes.
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
}

impl TryFrom<EbpfFlowEvent> for FlowEvent {
    type Error = EbpfError;

    fn try_from(event: EbpfFlowEvent) -> Result<Self, Self::Error> {
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
            ts_nanos: event.ts_nanos,
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
        let flow = FlowEvent::try_from(ev).unwrap();
        assert_eq!(flow.src_ip.to_string(), "10.0.0.1");
        assert_eq!(flow.dst_ip.to_string(), "10.0.0.2");
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.interface_index, 2);
        assert_eq!(flow.direction, Direction::Ingress);
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
        assert!(FlowEvent::try_from(ev).is_err());
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
            FlowEvent::try_from(event),
            Err(EbpfError::UnsupportedDirection(99))
        ));
    }
}
