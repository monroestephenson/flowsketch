//! Minimal classic-pcap writer. Used by the synthetic trace generator and
//! by tests; always writes nanosecond-timestamp Ethernet pcap.

use std::io::Write;
use std::net::IpAddr;

use crate::PcapError;

pub struct PcapWriter<W: Write> {
    writer: W,
    packets_written: u64,
    max_written_payload: usize,
}

impl<W: Write> PcapWriter<W> {
    const COMPACT_PAYLOAD_LIMIT: usize = 64;

    /// Create a compact synthetic-trace writer. Packet headers retain the
    /// requested wire length, but at most 64 zero payload bytes are stored.
    pub fn new(writer: W) -> Result<Self, PcapError> {
        Self::with_payload_limit(writer, Self::COMPACT_PAYLOAD_LIMIT)
    }

    /// Create a writer that stores the full zero payload up to the protocol's
    /// maximum packet length. This is intended for physical packet replay.
    pub fn new_full_payload(writer: W) -> Result<Self, PcapError> {
        Self::with_payload_limit(writer, usize::MAX)
    }

    fn with_payload_limit(mut writer: W, max_written_payload: usize) -> Result<Self, PcapError> {
        // Nanosecond magic, version 2.4, Ethernet.
        writer.write_all(&0xA1B2_3C4Du32.to_le_bytes())?;
        writer.write_all(&2u16.to_le_bytes())?;
        writer.write_all(&4u16.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?; // thiszone
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&65_535u32.to_le_bytes())?; // snaplen
        writer.write_all(&crate::linktype::ETHERNET.to_le_bytes())?;
        Ok(PcapWriter {
            writer,
            packets_written: 0,
            max_written_payload,
        })
    }

    pub fn packets_written(&self) -> u64 {
        self.packets_written
    }

    fn write_record(
        &mut self,
        ts_nanos: u64,
        original_len: u32,
        frame: &[u8],
    ) -> Result<(), PcapError> {
        self.writer
            .write_all(&((ts_nanos / 1_000_000_000) as u32).to_le_bytes())?;
        self.writer
            .write_all(&((ts_nanos % 1_000_000_000) as u32).to_le_bytes())?;
        self.writer.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.writer.write_all(&original_len.to_le_bytes())?;
        self.writer.write_all(frame)?;
        self.packets_written += 1;
        Ok(())
    }

    /// Write a TCP packet with `payload_len` zero payload bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn write_tcp_packet(
        &mut self,
        ts_nanos: u64,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
        payload_len: u32,
    ) -> Result<(), PcapError> {
        let l4 = tcp_header(src_port, dst_port, tcp_flags);
        let original_len = original_frame_len(src, dst, l4.len(), payload_len);
        let frame = build_frame(src, dst, 6, &l4, payload_len, self.max_written_payload);
        self.write_record(ts_nanos, original_len, &frame)
    }

    /// Write a UDP packet with `payload_len` zero payload bytes.
    pub fn write_udp_packet(
        &mut self,
        ts_nanos: u64,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload_len: u32,
    ) -> Result<(), PcapError> {
        let l4 = udp_header(src_port, dst_port, payload_len as u16);
        let original_len = original_frame_len(src, dst, l4.len(), payload_len);
        let frame = build_frame(src, dst, 17, &l4, payload_len, self.max_written_payload);
        self.write_record(ts_nanos, original_len, &frame)
    }
}

fn original_frame_len(src: IpAddr, dst: IpAddr, l4_len: usize, payload_len: u32) -> u32 {
    let requested_payload = usize::try_from(payload_len).unwrap_or(usize::MAX);
    let len = match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            14 + 20 + l4_len + requested_payload.min(65_535usize.saturating_sub(20 + l4_len))
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            14 + 40 + l4_len + requested_payload.min(65_535usize.saturating_sub(l4_len))
        }
        _ => 14 + 20 + l4_len,
    };
    len as u32
}

fn tcp_header(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut h = Vec::with_capacity(20);
    h.extend_from_slice(&src_port.to_be_bytes());
    h.extend_from_slice(&dst_port.to_be_bytes());
    h.extend_from_slice(&[0; 8]); // seq, ack
    h.push(0x50); // data offset 5
    h.push(flags);
    h.extend_from_slice(&[0xFF, 0xFF]); // window
    h.extend_from_slice(&[0; 4]); // checksum, urgent
    h
}

fn udp_header(src_port: u16, dst_port: u16, payload_len: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(8);
    h.extend_from_slice(&src_port.to_be_bytes());
    h.extend_from_slice(&dst_port.to_be_bytes());
    h.extend_from_slice(&(8 + payload_len).to_be_bytes());
    h.extend_from_slice(&[0; 2]); // checksum
    h
}

/// Assemble Ethernet + IP + L4 + zero payload. Compact writers cap stored
/// payload while retaining the requested IP length; full-payload writers cap
/// only at the protocol's maximum representable packet length.
fn build_frame(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    l4: &[u8],
    payload_len: u32,
    max_written_payload: usize,
) -> Vec<u8> {
    let requested_payload = usize::try_from(payload_len).unwrap_or(usize::MAX);
    let protocol_payload_limit = match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 65_535usize.saturating_sub(20 + l4.len()),
        (IpAddr::V6(_), IpAddr::V6(_)) => 65_535usize.saturating_sub(l4.len()),
        _ => 65_535usize.saturating_sub(20 + l4.len()),
    };
    let written_payload = requested_payload
        .min(max_written_payload)
        .min(protocol_payload_limit);

    let mut frame = Vec::with_capacity(14 + 40 + l4.len() + written_payload);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst MAC
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src MAC

    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            let total_len = 20 + l4.len() as u32 + payload_len;
            frame.push(0x45);
            frame.push(0);
            frame.extend_from_slice(&(total_len.min(65_535) as u16).to_be_bytes());
            frame.extend_from_slice(&[0, 0, 0x40, 0]); // id, DF
            frame.push(64);
            frame.push(protocol);
            frame.extend_from_slice(&[0, 0]); // checksum (unset)
            frame.extend_from_slice(&s.octets());
            frame.extend_from_slice(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            frame.extend_from_slice(&0x86DDu16.to_be_bytes());
            frame.push(0x60);
            frame.extend_from_slice(&[0, 0, 0]);
            let plen = (l4.len() as u32 + payload_len).min(65_535) as u16;
            frame.extend_from_slice(&plen.to_be_bytes());
            frame.push(protocol);
            frame.push(64); // hop limit
            frame.extend_from_slice(&s.octets());
            frame.extend_from_slice(&d.octets());
        }
        _ => {
            // Mixed families cannot occur from the generator; write v4 zeros.
            frame.extend_from_slice(&0x0800u16.to_be_bytes());
            frame.extend_from_slice(&[0x45, 0, 0, 28, 0, 0, 0, 0, 64, protocol, 0, 0]);
            frame.extend_from_slice(&[0; 8]);
        }
    }
    frame.extend_from_slice(l4);
    frame.resize(frame.len() + written_payload, 0);
    frame
}
