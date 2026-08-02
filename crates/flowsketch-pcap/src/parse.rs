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
    parse_packet_with_wire_len(link, data, u32::try_from(data.len()).ok()?)
}

/// Parse a possibly snaplen-truncated capture. `wire_len` is the packet's
/// original link-layer length from the capture boundary (pcap record or
/// TPACKET header). Network-layer length fields must fit inside it, while the
/// captured bytes must contain every header this parser inspects.
pub fn parse_packet_with_wire_len(link: u32, data: &[u8], wire_len: u32) -> Option<FlowEvent> {
    let wire_len = usize::try_from(wire_len).ok()?;
    if data.len() > wire_len {
        return None;
    }
    match link {
        linktype::ETHERNET => parse_ethernet(data, wire_len),
        linktype::RAW_IP => parse_ip(data, wire_len),
        linktype::LINUX_SLL => {
            // 16-byte SLL header; EtherType in the last two bytes.
            if data.len() < 16 {
                return None;
            }
            let ethertype = u16::from_be_bytes([data[14], data[15]]);
            parse_l3(ethertype, &data[16..], wire_len.checked_sub(16)?)
        }
        _ => None,
    }
}

fn parse_ethernet(data: &[u8], wire_len: usize) -> Option<FlowEvent> {
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
    parse_l3(ethertype, &data[offset..], wire_len.checked_sub(offset)?)
}

fn parse_l3(ethertype: u16, data: &[u8], wire_len: usize) -> Option<FlowEvent> {
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(data, wire_len),
        ETHERTYPE_IPV6 => parse_ipv6(data, wire_len),
        _ => None,
    }
}

fn parse_ip(data: &[u8], wire_len: usize) -> Option<FlowEvent> {
    match data.first()? >> 4 {
        4 => parse_ipv4(data, wire_len),
        6 => parse_ipv6(data, wire_len),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8], wire_len: usize) -> Option<FlowEvent> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len < ihl || total_len > wire_len {
        return None;
    }
    let protocol = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let frag = u16::from_be_bytes([data[6], data[7]]);
    let fragment_offset = frag & 0x1FFF;
    let l4 = if fragment_offset == 0 {
        let captured_end = total_len.min(data.len());
        parse_l4(protocol, &data[ihl..captured_end], total_len - ihl)?
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
        bytes: total_len as u32,
        packets: 1,
        ..FlowEvent::default()
    })
}

fn parse_ipv6(data: &[u8], wire_len: usize) -> Option<FlowEvent> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    // IPv6 jumbograms need the Hop-by-Hop Jumbo Payload option and are not
    // supported by either capture parser.
    if payload_len == 0 {
        return None;
    }
    let packet_len = 40usize.checked_add(payload_len)?;
    if packet_len > wire_len {
        return None;
    }
    let mut next_header = data[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    // Walk the same bounded extension-header set as the tc parser. Every
    // offset must fit both the declared packet and the captured prefix.
    let mut offset = 40usize;
    let mut l4 = L4Info::default();
    let mut non_first_fragment = false;
    for _ in 0..6 {
        match next_header {
            0 | 43 | 51 | 60 => {
                let fixed_end = offset.checked_add(8)?;
                if fixed_end > packet_len || fixed_end > data.len() {
                    return None;
                }
                let len = if next_header == 51 {
                    (data[offset + 1] as usize + 2).checked_mul(4)?
                } else {
                    8usize.checked_add(data[offset + 1] as usize * 8)?
                };
                let next_offset = offset.checked_add(len)?;
                if len < 8 || next_offset > packet_len || next_offset > data.len() {
                    return None;
                }
                next_header = data[offset];
                offset = next_offset;
            }
            44 => {
                let next_offset = offset.checked_add(8)?;
                if next_offset > packet_len || next_offset > data.len() {
                    return None;
                }
                let frag_offset = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) >> 3;
                next_header = data[offset];
                offset = next_offset;
                if frag_offset != 0 {
                    non_first_fragment = true;
                    break;
                }
            }
            _ => {
                let captured_end = packet_len.min(data.len());
                l4 = parse_l4(
                    next_header,
                    data.get(offset..captured_end)?,
                    packet_len.checked_sub(offset)?,
                )?;
                break;
            }
        }
    }
    if matches!(next_header, 0 | 43 | 44 | 51 | 60) && !non_first_fragment {
        return None;
    }

    Some(FlowEvent {
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
        src_port: l4.src_port,
        dst_port: l4.dst_port,
        protocol: next_header,
        tcp_flags: l4.tcp_flags,
        bytes: packet_len as u32,
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

fn parse_l4(protocol: u8, data: &[u8], wire_len: usize) -> Option<L4Info> {
    match protocol {
        6 => {
            if data.len() < 14 {
                return None;
            }
            let header_len = usize::from(data[12] >> 4) * 4;
            if header_len < 20 || header_len > wire_len || header_len > data.len() {
                return None;
            }
            Some(L4Info {
                src_port: u16::from_be_bytes([data[0], data[1]]),
                dst_port: u16::from_be_bytes([data[2], data[3]]),
                tcp_flags: data[13],
            })
        }
        17 => {
            if data.len() < 8 {
                return None;
            }
            let udp_len = u16::from_be_bytes([data[4], data[5]]) as usize;
            if udp_len < 8 || udp_len > wire_len {
                return None;
            }
            Some(L4Info {
                src_port: u16::from_be_bytes([data[0], data[1]]),
                dst_port: u16::from_be_bytes([data[2], data[3]]),
                tcp_flags: 0,
            })
        }
        _ => Some(L4Info::default()),
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
    fn ipv6_with_truncated_extension_header_is_rejected() {
        let mut f = Vec::new();
        f.extend_from_slice(&[0u8; 12]); // MACs
        f.extend_from_slice(&0x86DDu16.to_be_bytes());
        f.push(0x60); // version 6
        f.extend_from_slice(&[0, 0, 0]);
        f.extend_from_slice(&100u16.to_be_bytes()); // payload length
        f.push(0); // next header: hop-by-hop
        f.push(64); // hop limit
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Hop-by-hop header: next = TCP, ext len 3 (= 32 bytes total), but
        // the capture ends right after these 8 bytes.
        f.push(6); // next header: TCP
        f.push(3); // hdr ext len
        f.extend_from_slice(&[0; 6]);

        assert!(parse_packet(linktype::ETHERNET, &f).is_none());
    }

    #[test]
    fn attacker_controlled_ip_lengths_cannot_inflate_byte_counts() {
        let mut inflated_v4 = ipv4_tcp_frame();
        inflated_v4[16..18].copy_from_slice(&1_500u16.to_be_bytes());
        assert!(parse_packet(linktype::ETHERNET, &inflated_v4).is_none());

        let mut undersized_v4 = ipv4_tcp_frame();
        undersized_v4[16..18].copy_from_slice(&10u16.to_be_bytes());
        assert!(parse_packet(linktype::ETHERNET, &undersized_v4).is_none());

        let mut inflated_v6 = vec![0u8; 14 + 40];
        inflated_v6[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        inflated_v6[14] = 0x60;
        inflated_v6[18..20].copy_from_slice(&1_000u16.to_be_bytes());
        inflated_v6[20] = 59; // no next header
        assert!(parse_packet(linktype::ETHERNET, &inflated_v6).is_none());
    }

    #[test]
    fn snaplen_truncation_uses_original_wire_bound() {
        let full = ipv4_tcp_frame();
        let captured = &full[..34]; // Ethernet + complete IPv4 header only.
        assert!(parse_packet_with_wire_len(linktype::ETHERNET, captured, 54).is_none());

        // All inspected headers are present, while the payload is truncated.
        let mut captured = full;
        captured[16..18].copy_from_slice(&1_500u16.to_be_bytes());
        let event = parse_packet_with_wire_len(linktype::ETHERNET, &captured, 1_514)
            .expect("valid snaplen-truncated packet rejected");
        assert_eq!(event.bytes, 1_500);
    }

    #[test]
    fn truncated_frames_do_not_panic() {
        let frame = ipv4_tcp_frame();
        for cut in 0..frame.len() {
            let _ = parse_packet(linktype::ETHERNET, &frame[..cut]);
        }
    }

    #[test]
    fn deterministic_arbitrary_frames_do_not_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..512usize {
            let mut frame = vec![0; len];
            for byte in &mut frame {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            for link in [
                linktype::ETHERNET,
                linktype::RAW_IP,
                linktype::LINUX_SLL,
                u32::MAX,
            ] {
                let _ = parse_packet(link, &frame);
            }
        }
    }
}
