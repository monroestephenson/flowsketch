//! Minimal classic-pcap writer. Used by the synthetic trace generator and
//! by tests; always writes nanosecond-timestamp Ethernet pcap.

use std::io::Write;
use std::net::IpAddr;

use crate::PcapError;

pub struct PcapWriter<W: Write> {
    writer: W,
    packets_written: u64,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W) -> Result<Self, PcapError> {
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
        })
    }

    pub fn packets_written(&self) -> u64 {
        self.packets_written
    }

    fn write_record(&mut self, ts_nanos: u64, frame: &[u8]) -> Result<(), PcapError> {
        self.writer
            .write_all(&((ts_nanos / 1_000_000_000) as u32).to_le_bytes())?;
        self.writer
            .write_all(&((ts_nanos % 1_000_000_000) as u32).to_le_bytes())?;
        self.writer.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.writer.write_all(&(frame.len() as u32).to_le_bytes())?;
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
        let frame = build_frame(src, dst, 6, &l4, payload_len);
        self.write_record(ts_nanos, &frame)
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
        let frame = build_frame(src, dst, 17, &l4, payload_len);
        self.write_record(ts_nanos, &frame)
    }
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

/// Assemble Ethernet + IP + L4 + zero payload. The written payload is
/// capped so synthetic traces stay small; the IP total-length field still
/// reflects the requested size, which is what the parser reports as bytes.
fn build_frame(src: IpAddr, dst: IpAddr, protocol: u8, l4: &[u8], payload_len: u32) -> Vec<u8> {
    const MAX_WRITTEN_PAYLOAD: usize = 64;
    let written_payload = (payload_len as usize).min(MAX_WRITTEN_PAYLOAD);

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
    frame.extend_from_slice(&vec![0u8; written_payload]);
    frame
}
