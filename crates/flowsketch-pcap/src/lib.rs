//! Offline pcap replay: a dependency-free classic-pcap reader plus
//! Ethernet/IPv4/IPv6/TCP/UDP header parsing into `FlowEvent`s.
//!
//! Headers only — payload bytes are never inspected or retained.

use std::io::Read;

use thiserror::Error;

use flowsketch_core::{Direction, FlowEvent};

pub mod parse;
pub mod writer;

pub use parse::{parse_packet, parse_packet_with_wire_len};
pub use writer::PcapWriter;

pub type BorrowedPacket<'a> = (u64, u32, &'a [u8]);

#[derive(Debug, Error)]
pub enum PcapError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a pcap file (bad magic 0x{0:08x}); pcapng is not supported yet")]
    BadMagic(u32),
    #[error("truncated pcap record")]
    Truncated,
    #[error("pcap record has an out-of-range sub-second timestamp")]
    InvalidTimestamp,
}

/// Link types FlowSketch can parse.
pub mod linktype {
    pub const ETHERNET: u32 = 1; // LINKTYPE_EN10MB
    pub const RAW_IP: u32 = 101; // LINKTYPE_RAW
    pub const LINUX_SLL: u32 = 113; // LINKTYPE_LINUX_SLL
}

/// Streaming reader for classic pcap files (both byte orders, microsecond
/// and nanosecond timestamp variants).
pub struct PcapReader<R: Read> {
    reader: R,
    swapped: bool,
    /// Multiplier converting the sub-second field to nanoseconds.
    subsec_to_nanos: u64,
    linktype: u32,
    packets_read: u64,
}

const MAGIC_USEC: u32 = 0xA1B2_C3D4;
const MAGIC_NSEC: u32 = 0xA1B2_3C4D;

impl<R: Read> PcapReader<R> {
    pub fn new(mut reader: R) -> Result<Self, PcapError> {
        let mut header = [0u8; 24];
        reader.read_exact(&mut header)?;
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let (swapped, subsec_to_nanos) = match magic {
            MAGIC_USEC => (false, 1_000),
            MAGIC_NSEC => (false, 1),
            m if m.swap_bytes() == MAGIC_USEC => (true, 1_000),
            m if m.swap_bytes() == MAGIC_NSEC => (true, 1),
            m => return Err(PcapError::BadMagic(m)),
        };
        let read_u32 = |b: &[u8]| -> u32 {
            let v = u32::from_le_bytes(b.try_into().unwrap());
            if swapped {
                v.swap_bytes()
            } else {
                v
            }
        };
        let linktype = read_u32(&header[20..24]);
        Ok(PcapReader {
            reader,
            swapped,
            subsec_to_nanos,
            linktype,
            packets_read: 0,
        })
    }

    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    pub fn packets_read(&self) -> u64 {
        self.packets_read
    }

    fn u32_at(&self, b: &[u8]) -> u32 {
        let v = u32::from_le_bytes(b.try_into().unwrap());
        if self.swapped {
            v.swap_bytes()
        } else {
            v
        }
    }

    /// Next raw packet as `(ts_nanos, original_len, captured_bytes)`, or
    /// `None` at end of file.
    pub fn next_packet(&mut self) -> Result<Option<(u64, u32, Vec<u8>)>, PcapError> {
        let mut data = Vec::new();
        let Some((ts_nanos, origlen, _)) = self.next_packet_into(&mut data)? else {
            return Ok(None);
        };
        Ok(Some((ts_nanos, origlen, data)))
    }

    /// Next raw packet using a caller-owned scratch buffer.
    ///
    /// This avoids allocating a fresh packet buffer for every pcap record in
    /// hot replay/benchmark loops while keeping `next_packet` available for
    /// callers that want owned packet bytes.
    pub fn next_packet_into<'a>(
        &mut self,
        data: &'a mut Vec<u8>,
    ) -> Result<Option<BorrowedPacket<'a>>, PcapError> {
        let mut rec = [0u8; 16];
        match self.reader.read_exact(&mut rec) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let ts_sec = self.u32_at(&rec[0..4]) as u64;
        let ts_subsec = self.u32_at(&rec[4..8]) as u64;
        let caplen = self.u32_at(&rec[8..12]) as usize;
        let origlen = self.u32_at(&rec[12..16]);
        // Sanity cap: no sane snapshot length exceeds 256 KiB.
        if caplen > 256 * 1024 {
            return Err(PcapError::Truncated);
        }
        if u64::from(origlen) < caplen as u64 {
            return Err(PcapError::Truncated);
        }
        if ts_subsec >= 1_000_000_000 / self.subsec_to_nanos {
            return Err(PcapError::InvalidTimestamp);
        }
        data.resize(caplen, 0);
        self.reader
            .read_exact(data)
            .map_err(|_| PcapError::Truncated)?;
        self.packets_read += 1;
        let ts_nanos = ts_sec * 1_000_000_000 + ts_subsec * self.subsec_to_nanos;
        Ok(Some((ts_nanos, origlen, data.as_slice())))
    }

    /// Next parseable flow event, skipping packets that are not
    /// IPv4/IPv6 over a supported link type.
    pub fn next_event(&mut self) -> Result<Option<FlowEvent>, PcapError> {
        let mut data = Vec::new();
        self.next_event_into(&mut data)
    }

    /// Next parseable flow event using a caller-owned scratch buffer.
    pub fn next_event_into(&mut self, data: &mut Vec<u8>) -> Result<Option<FlowEvent>, PcapError> {
        loop {
            match self.next_packet_into(data)? {
                None => return Ok(None),
                Some((ts_nanos, origlen, data)) => {
                    if let Some(mut ev) = parse_packet_with_wire_len(self.linktype, data, origlen) {
                        ev.ts_nanos = ts_nanos;
                        // Bytes on the wire, not bytes captured.
                        if ev.bytes == 0 {
                            ev.bytes = origlen;
                        }
                        ev.direction = Direction::Unknown;
                        return Ok(Some(ev));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::PcapWriter;
    use std::io::Cursor;
    use std::net::IpAddr;

    #[test]
    fn write_then_read_round_trips() {
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf).unwrap();
            w.write_tcp_packet(
                1_700_000_000_000_000_000,
                "10.0.1.10".parse().unwrap(),
                "10.0.2.50".parse().unwrap(),
                40_000,
                443,
                0x18, // PSH|ACK
                1_200,
            )
            .unwrap();
            w.write_udp_packet(
                1_700_000_001_000_000_000,
                "10.0.1.11".parse().unwrap(),
                "10.0.2.51".parse().unwrap(),
                50_000,
                53,
                300,
            )
            .unwrap();
            w.write_tcp_packet(
                1_700_000_002_000_000_000,
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                1234,
                8080,
                0x02, // SYN
                600,
            )
            .unwrap();
        }

        let mut r = PcapReader::new(Cursor::new(buf)).unwrap();
        assert_eq!(r.linktype(), linktype::ETHERNET);

        let e1 = r.next_event().unwrap().unwrap();
        assert_eq!(e1.src_ip, "10.0.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(e1.dst_ip, "10.0.2.50".parse::<IpAddr>().unwrap());
        assert_eq!((e1.src_port, e1.dst_port), (40_000, 443));
        assert_eq!(e1.protocol, 6);
        assert_eq!(e1.tcp_flags, 0x18);
        assert_eq!(e1.ts_nanos, 1_700_000_000_000_000_000);
        assert!(e1.bytes >= 1_200);

        let e2 = r.next_event().unwrap().unwrap();
        assert_eq!(e2.protocol, 17);
        assert_eq!((e2.src_port, e2.dst_port), (50_000, 53));

        let e3 = r.next_event().unwrap().unwrap();
        assert_eq!(e3.src_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(e3.protocol, 6);
        assert_eq!(e3.tcp_flags, 0x02);

        assert!(r.next_event().unwrap().is_none());
    }

    #[test]
    fn rejects_out_of_range_subsecond_timestamp() {
        let mut bytes = Vec::new();
        PcapWriter::new(&mut bytes)
            .unwrap()
            .write_udp_packet(
                1_700_000_000_000_000_000,
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                1234,
                53,
                64,
            )
            .unwrap();
        // Global header is 24 bytes; record timestamp sub-seconds starts at
        // byte 28. PcapWriter emits nanosecond-resolution files.
        bytes[28..32].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        assert!(matches!(
            reader.next_packet(),
            Err(PcapError::InvalidTimestamp)
        ));
    }

    #[test]
    fn full_payload_writer_emits_wire_sized_frames() {
        let mut compact = Vec::new();
        PcapWriter::new(&mut compact)
            .unwrap()
            .write_tcp_packet(
                1,
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                1234,
                443,
                0x18,
                1_200,
            )
            .unwrap();
        let mut full = Vec::new();
        PcapWriter::new_full_payload(&mut full)
            .unwrap()
            .write_tcp_packet(
                1,
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
                1234,
                443,
                0x18,
                1_200,
            )
            .unwrap();

        let (_, compact_len, compact_frame) = PcapReader::new(Cursor::new(compact))
            .unwrap()
            .next_packet()
            .unwrap()
            .unwrap();
        let (_, full_len, full_frame) = PcapReader::new(Cursor::new(full))
            .unwrap()
            .next_packet()
            .unwrap()
            .unwrap();
        assert_eq!(compact_len, 1_254);
        assert_eq!(compact_frame.len(), 118);
        assert_eq!(full_len, 1_254);
        assert_eq!(full_frame.len(), 1_254);
    }

    #[test]
    fn rejects_non_pcap_input() {
        let junk = vec![0u8; 64];
        assert!(matches!(
            PcapReader::new(Cursor::new(junk)),
            Err(PcapError::BadMagic(_))
        ));
    }
}
