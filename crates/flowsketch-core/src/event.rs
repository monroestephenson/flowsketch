//! The normalized flow event: headers and metadata only, never payload.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// Traffic direction relative to the observation point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Ingress,
    Egress,
    Unknown,
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
            Direction::Unknown => "unknown",
        }
    }
}

/// One observed flow sample (a packet or a pre-aggregated flow record).
///
/// This deliberately excludes payload content: the privacy posture is
/// headers and metadata only by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEvent {
    pub ts_nanos: u64,

    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,

    pub bytes: u32,
    pub packets: u32,

    pub direction: Direction,
    pub tcp_flags: u8,
    pub interface_index: u32,

    pub node_id: u64,
    pub namespace_id: Option<u64>,
    pub pod_id: Option<u64>,
    pub service_id: Option<u64>,
}

impl Default for FlowEvent {
    fn default() -> Self {
        FlowEvent {
            ts_nanos: 0,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            bytes: 0,
            packets: 1,
            direction: Direction::Unknown,
            tcp_flags: 0,
            interface_index: 0,
            node_id: 0,
            namespace_id: None,
            pod_id: None,
            service_id: None,
        }
    }
}

/// IANA protocol numbers FlowSketch understands by name.
pub mod protocol {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;

    /// Map a protocol number to a lowercase name, falling back to the number.
    pub fn name(proto: u8) -> String {
        match proto {
            ICMP => "icmp".to_string(),
            TCP => "tcp".to_string(),
            UDP => "udp".to_string(),
            ICMPV6 => "icmpv6".to_string(),
            other => other.to_string(),
        }
    }

    /// Parse a protocol name or number.
    pub fn parse(s: &str) -> Option<u8> {
        match s.to_ascii_lowercase().as_str() {
            "icmp" => Some(ICMP),
            "tcp" => Some(TCP),
            "udp" => Some(UDP),
            "icmpv6" => Some(ICMPV6),
            other => other.parse::<u8>().ok(),
        }
    }
}
