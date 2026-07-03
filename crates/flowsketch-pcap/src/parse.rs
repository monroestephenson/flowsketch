//! L2/L3/L4 header parsing. Parses exactly enough to build a `FlowEvent`:
//! addresses, ports, protocol, TCP flags, and on-wire byte counts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flowsketch_core::FlowEvent;

use crate::linktype;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

/// Parse a captured packet into a `FlowEvent` (timestamp left at 0 for the
/// caller to fill). Returns `None` for frames that are not IPv4/IPv6 or use
/// an unsupported link type.
pub fn parse_packet(link: u32, data: &[u8]) -> Option<FlowEvent> {
    match link {
        linktype::ETHERNET => parse_ethernet(data),
        linktype::RAW_IP => parse_ip(data),
        linktype::LINUX_SLL => {
            // 16-byte SLL header; EtherType in the last two bytes.
            if data.len() < 16 {
                return None;
            }
            let ethertype = u16::from_be_bytes([data[14], data[15]]);
            parse_l3(ethertype, &data[16..])
        }
        _ => None,
    }
}

fn parse_ethernet(data: &[u8]) -> Option<FlowEvent> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;
    // Unwrap up to two VLAN tags (802.1Q / QinQ).
    for _ in 0..2 {
        if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
            if data.len() < offset + 4 {
                return None;
            }
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        }
    }
    parse_l3(ethertype, &data[offset..])
}

fn parse_l3(ethertype: u16, data: &[u8]) -> Option<FlowEvent> {
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(data),
        ETHERTYPE_IPV6 => parse_ipv6(data),
        _ => None,
    }
}

fn parse_ip(data: &[u8]) -> Option<FlowEvent> {
    match data.first()? >> 4 {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<FlowEvent> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as u32;
    let protocol = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let frag = u16::from_be_bytes([data[6], data[7]]);
    let fragment_offset = frag & 0x1FFF;
    let l4 = if fragment_offset == 0 {
        parse_l4(protocol, &data[ihl..])
    } else {
        // Non-first fragment: no L4 header present.
        L4Info::default()
    };

    Some(FlowEvent {
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        src_port: l4.src_port,
        dst_port: l4.dst_port,
        protocol,
        tcp_flags: l4.tcp_flags,
        bytes: total_len,
        packets: 1,
        ..FlowEvent::default()
    })
}

fn parse_ipv6(data: &[u8]) -> Option<FlowEvent> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as u32;
    let mut next_header = data[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    // Walk common extension headers to find the transport header.
    let mut offset = 40usize;
    let mut l4 = L4Info::default();
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-hop, routing, destination options:
                // [next_header, hdr_ext_len (8-byte units, excl. first 8)].
                if data.len() < offset + 8 {
                    break;
                }
                let len = 8 + data[offset + 1] as usize * 8;
                next_header = data[offset];
                offset += len;
            }
            44 => {
                // Fragment header: fixed 8 bytes. Only the first fragment
                // carries the L4 header.
                if data.len() < offset + 8 {
                    break;
                }
                let frag_offset = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) >> 3;
                let nh = data[offset];
                offset += 8;
                if frag_offset != 0 {
                    next_header = nh;
                    break;
                }
                next_header = nh;
            }
            _ => {
                l4 = parse_l4(next_header, data.get(offset..)?);
                break;
            }
        }
    }

    Some(FlowEvent {
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
        src_port: l4.src_port,
        dst_port: l4.dst_port,
        protocol: next_header,
        tcp_flags: l4.tcp_flags,
        bytes: 40 + payload_len,
        packets: 1,
        ..FlowEvent::default()
    })
}

#[derive(Default)]
struct L4Info {
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
}

fn parse_l4(protocol: u8, data: &[u8]) -> L4Info {
    match protocol {
        6 => {
            // TCP: ports at 0..4, flags at byte 13.
            if data.len() >= 14 {
                L4Info {
                    src_port: u16::from_be_bytes([data[0], data[1]]),
                    dst_port: u16::from_be_bytes([data[2], data[3]]),
                    tcp_flags: data[13],
                }
            } else {
                L4Info::default()
            }
        }
        17 => {
            // UDP: ports at 0..4.
            if data.len() >= 8 {
                L4Info {
                    src_port: u16::from_be_bytes([data[0], data[1]]),
                    dst_port: u16::from_be_bytes([data[2], data[3]]),
                    tcp_flags: 0,
                }
            } else {
                L4Info::default()
            }
        }
        _ => L4Info::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built Ethernet + IPv4 + TCP frame.
    fn ipv4_tcp_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0u8; 12]); // MACs
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4 header, 20 bytes
        f.push(0x45); // version 4, IHL 5
        f.push(0);
        f.extend_from_slice(&40u16.to_be_bytes()); // total length
        f.extend_from_slice(&[0, 0, 0, 0]); // id, frag
        f.push(64); // ttl
        f.push(6); // protocol TCP
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&[192, 168, 1, 2]); // src
        f.extend_from_slice(&[10, 0, 0, 9]); // dst
        // TCP header, 20 bytes
        f.extend_from_slice(&12345u16.to_be_bytes());
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(&[0; 8]); // seq, ack
        f.push(0x50); // data offset
        f.push(0x12); // SYN|ACK
        f.extend_from_slice(&[0; 4]); // window, checksum
        f.extend_from_slice(&[0; 2]); // urgent
        f
    }

    #[test]
    fn parses_ipv4_tcp() {
        let e = parse_packet(linktype::ETHERNET, &ipv4_tcp_frame()).unwrap();
        assert_eq!(e.src_ip.to_string(), "192.168.1.2");
        assert_eq!(e.dst_ip.to_string(), "10.0.0.9");
        assert_eq!((e.src_port, e.dst_port), (12345, 443));
        assert_eq!(e.protocol, 6);
        assert_eq!(e.tcp_flags, 0x12);
        assert_eq!(e.bytes, 40);
    }

    #[test]
    fn parses_vlan_tagged_frame() {
        let plain = ipv4_tcp_frame();
        let mut tagged = plain[..12].to_vec();
        tagged.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x64]); // VLAN 100
        tagged.extend_from_slice(&plain[12..]); // original ethertype + payload
        let e = parse_packet(linktype::ETHERNET, &tagged).unwrap();
        assert_eq!(e.dst_port, 443);
    }

    #[test]
    fn non_ip_frames_are_skipped() {
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes()); // ARP
        arp.extend_from_slice(&[0u8; 28]);
        assert!(parse_packet(linktype::ETHERNET, &arp).is_none());
    }

    #[test]
    fn truncated_frames_do_not_panic() {
        let frame = ipv4_tcp_frame();
        for cut in 0..frame.len() {
            let _ = parse_packet(linktype::ETHERNET, &frame[..cut]);
        }
    }
}
