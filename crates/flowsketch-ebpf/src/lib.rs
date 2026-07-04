//! eBPF collector scaffolding.
//!
//! This crate intentionally does not claim to load a kernel program yet.
//! It defines the userspace/kernel contract that a future tc/XDP backend
//! must satisfy: extract packet metadata into the same normalized event
//! shape as the pcap and AF_PACKET sources, then feed the existing runtime.
//! The sketch planner and sketch state stay in userspace.

use flowsketch_core::FlowEvent;
use thiserror::Error;

/// Stable userspace representation of the packet facts an eBPF collector
/// should emit. Keep this header-only and verifier-friendly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfFlowEvent {
    pub ts_nanos: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_version: u8,
    pub bytes: u32,
    pub tcp_flags: u8,
    pub interface_index: u32,
}

#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("unsupported IP version {0}")]
    UnsupportedIpVersion(u8),
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
        Ok(FlowEvent {
            ts_nanos: event.ts_nanos,
            src_ip,
            dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            bytes: event.bytes,
            packets: 1,
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
            protocol: 6,
            ip_version: 4,
            bytes: 1500,
            tcp_flags: 0x12,
            interface_index: 2,
        };
        let flow = FlowEvent::try_from(ev).unwrap();
        assert_eq!(flow.src_ip.to_string(), "10.0.0.1");
        assert_eq!(flow.dst_ip.to_string(), "10.0.0.2");
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.interface_index, 2);
    }

    #[test]
    fn rejects_unknown_ip_version() {
        let ev = EbpfFlowEvent {
            ts_nanos: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            ip_version: 5,
            bytes: 0,
            tcp_flags: 0,
            interface_index: 0,
        };
        assert!(FlowEvent::try_from(ev).is_err());
    }
}
