//! Logical dimensions of a flow event, addressable from queries by dotted
//! names (`src.ip`, `dst.port`, `protocol`, ...).

use std::fmt;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::event::{protocol, FlowEvent};

/// A logical field of `FlowEvent` that queries can group by, filter on, or
/// measure over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Field {
    SrcIp,
    DstIp,
    SrcPort,
    DstPort,
    Protocol,
    TcpFlags,
    Direction,
    Bytes,
    Packets,
    InterfaceIndex,
    NodeId,
}

impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Field::SrcIp => "src.ip",
            Field::DstIp => "dst.ip",
            Field::SrcPort => "src.port",
            Field::DstPort => "dst.port",
            Field::Protocol => "protocol",
            Field::TcpFlags => "tcp.flags",
            Field::Direction => "direction",
            Field::Bytes => "bytes",
            Field::Packets => "packets",
            Field::InterfaceIndex => "interface.index",
            Field::NodeId => "node.id",
        }
    }

    /// A Prometheus-safe label name for this field (`src.ip` -> `src_ip`).
    pub fn label_name(self) -> String {
        self.name().replace('.', "_")
    }

    /// Whether the field is usable as the value of `sum`/`heavy_hitters`.
    pub fn is_numeric_measure(self) -> bool {
        matches!(self, Field::Bytes | Field::Packets)
    }

    /// Extract this field's display value from an event. Display values are
    /// also the canonical key encoding: stable, self-describing, mergeable
    /// across nodes.
    pub fn extract(self, e: &FlowEvent) -> String {
        match self {
            Field::SrcIp => e.src_ip.to_string(),
            Field::DstIp => e.dst_ip.to_string(),
            Field::SrcPort => e.src_port.to_string(),
            Field::DstPort => e.dst_port.to_string(),
            Field::Protocol => protocol::name(e.protocol),
            Field::TcpFlags => e.tcp_flags.to_string(),
            Field::Direction => e.direction.name().to_string(),
            Field::Bytes => e.bytes.to_string(),
            Field::Packets => e.packets.to_string(),
            Field::InterfaceIndex => e.interface_index.to_string(),
            Field::NodeId => e.node_id.to_string(),
        }
    }

    /// Extract this field as a numeric measure value.
    pub fn extract_value(self, e: &FlowEvent) -> u64 {
        match self {
            Field::Bytes => e.bytes as u64,
            Field::Packets => e.packets as u64,
            Field::SrcPort => e.src_port as u64,
            Field::DstPort => e.dst_port as u64,
            Field::Protocol => e.protocol as u64,
            Field::TcpFlags => e.tcp_flags as u64,
            Field::InterfaceIndex => e.interface_index as u64,
            Field::NodeId => e.node_id,
            Field::SrcIp | Field::DstIp | Field::Direction => 0,
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Field {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "src.ip" => Ok(Field::SrcIp),
            "dst.ip" => Ok(Field::DstIp),
            "src.port" => Ok(Field::SrcPort),
            "dst.port" => Ok(Field::DstPort),
            "protocol" => Ok(Field::Protocol),
            "tcp.flags" => Ok(Field::TcpFlags),
            "direction" => Ok(Field::Direction),
            "bytes" => Ok(Field::Bytes),
            "packets" => Ok(Field::Packets),
            "interface.index" => Ok(Field::InterfaceIndex),
            "node.id" => Ok(Field::NodeId),
            other => Err(format!(
                "unknown field {other:?}; known fields: src.ip, dst.ip, src.port, dst.port, \
                 protocol, tcp.flags, direction, bytes, packets, interface.index, node.id"
            )),
        }
    }
}

impl TryFrom<String> for Field {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Field> for String {
    fn from(f: Field) -> String {
        f.name().to_string()
    }
}

/// Separator used when encoding a multi-field group key into bytes.
pub const GROUP_KEY_SEP: u8 = 0x1F; // ASCII unit separator

/// Encode the group-by key of `fields` for `event` into stable bytes.
pub fn group_key(fields: &[Field], event: &FlowEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 16);
    group_key_into(fields, event, &mut out);
    out
}

/// Encode the group-by key of `fields` into a caller-owned buffer.
pub fn group_key_into(fields: &[Field], event: &FlowEvent, out: &mut Vec<u8>) {
    out.clear();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(GROUP_KEY_SEP);
        }
        field_value_into(*f, event, out);
    }
}

/// Encode one field's canonical display value into a caller-owned buffer.
pub fn field_value_into(field: Field, event: &FlowEvent, out: &mut Vec<u8>) {
    match field {
        Field::SrcIp => append_ip(out, event.src_ip),
        Field::DstIp => append_ip(out, event.dst_ip),
        Field::SrcPort => append_decimal(out, event.src_port as u64),
        Field::DstPort => append_decimal(out, event.dst_port as u64),
        Field::Protocol => match event.protocol {
            protocol::ICMP => out.extend_from_slice(b"icmp"),
            protocol::TCP => out.extend_from_slice(b"tcp"),
            protocol::UDP => out.extend_from_slice(b"udp"),
            protocol::ICMPV6 => out.extend_from_slice(b"icmpv6"),
            other => append_decimal(out, other as u64),
        },
        Field::TcpFlags => append_decimal(out, event.tcp_flags as u64),
        Field::Direction => out.extend_from_slice(event.direction.name().as_bytes()),
        Field::Bytes => append_decimal(out, event.bytes as u64),
        Field::Packets => append_decimal(out, event.packets as u64),
        Field::InterfaceIndex => append_decimal(out, event.interface_index as u64),
        Field::NodeId => append_decimal(out, event.node_id),
    }
}

fn append_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(addr) => append_ipv4(out, addr),
        IpAddr::V6(addr) => write!(out, "{addr}").expect("write to Vec cannot fail"),
    }
}

fn append_ipv4(out: &mut Vec<u8>, addr: Ipv4Addr) {
    let octets = addr.octets();
    for (i, octet) in octets.into_iter().enumerate() {
        if i > 0 {
            out.push(b'.');
        }
        append_decimal(out, octet as u64);
    }
}

fn append_decimal(out: &mut Vec<u8>, mut value: u64) {
    if value == 0 {
        out.push(b'0');
        return;
    }

    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while value > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    out.extend_from_slice(&buf[i..]);
}

/// Decode a group key produced by `group_key` back into per-field values.
pub fn split_group_key(key: &[u8]) -> Vec<String> {
    if key.is_empty() {
        return Vec::new();
    }
    key.split(|&b| b == GROUP_KEY_SEP)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_round_trip() {
        for f in [
            Field::SrcIp,
            Field::DstIp,
            Field::SrcPort,
            Field::DstPort,
            Field::Protocol,
            Field::TcpFlags,
            Field::Direction,
            Field::Bytes,
            Field::Packets,
            Field::InterfaceIndex,
            Field::NodeId,
        ] {
            assert_eq!(f.name().parse::<Field>().unwrap(), f);
        }
    }

    #[test]
    fn group_key_round_trips() {
        let e = FlowEvent {
            src_ip: "10.0.1.5".parse().unwrap(),
            dst_ip: "10.0.2.7".parse().unwrap(),
            protocol: 6,
            ..FlowEvent::default()
        };
        let key = group_key(&[Field::SrcIp, Field::DstIp, Field::Protocol], &e);
        assert_eq!(split_group_key(&key), vec!["10.0.1.5", "10.0.2.7", "tcp"]);
    }
}
