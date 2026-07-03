//! `flowsketch synth`: reproducible synthetic pcap traces containing
//! background traffic, heavy talkers, and scanners — so replay, examples,
//! and benchmarks work without real captures.

use std::fs::File;
use std::io::BufWriter;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result};

use flowsketch_core::hash::splitmix64;
use flowsketch_pcap::PcapWriter;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        splitmix64(self.0)
    }
}

pub fn run(
    out: &Path,
    packets: u64,
    scanners: u32,
    heavy_talkers: u32,
    duration_secs: u64,
    seed: u64,
) -> Result<()> {
    let file =
        File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut w = PcapWriter::new(BufWriter::new(file)).context("cannot write pcap header")?;
    let mut rng = Rng(seed);

    let base_ts: u64 = 1_700_000_000_000_000_000;
    let span_nanos = duration_secs * 1_000_000_000;

    // Traffic mix: ~70% background, ~20% heavy talkers, ~10% scanners.
    let scanner_ips: Vec<Ipv4Addr> = (0..scanners)
        .map(|i| Ipv4Addr::new(10, 66, 0, (i + 1) as u8))
        .collect();
    let heavy_pairs: Vec<(Ipv4Addr, Ipv4Addr)> = (0..heavy_talkers)
        .map(|i| {
            (
                Ipv4Addr::new(10, 1, 1, (i + 10) as u8),
                Ipv4Addr::new(10, 2, 2, (i + 10) as u8),
            )
        })
        .collect();
    let scan_ports = [22u16, 80, 443, 5432, 6379];

    let mut scan_counter: u64 = 0;
    for i in 0..packets {
        // Timestamps advance monotonically with light jitter.
        let ts = base_ts + (i * span_nanos) / packets.max(1) + rng.next() % 1_000_000;
        let roll = rng.next() % 100;

        if roll < 10 && !scanner_ips.is_empty() {
            // Scanner: one source sweeping many distinct destinations.
            let src = scanner_ips[(rng.next() % scanner_ips.len() as u64) as usize];
            scan_counter += 1;
            let dst = Ipv4Addr::new(
                10,
                (100 + (scan_counter >> 16) % 100) as u8,
                ((scan_counter >> 8) & 0xFF) as u8,
                (scan_counter & 0xFF) as u8,
            );
            let port = scan_ports[(rng.next() % scan_ports.len() as u64) as usize];
            w.write_tcp_packet(
                ts,
                IpAddr::V4(src),
                IpAddr::V4(dst),
                40_000 + (rng.next() % 20_000) as u16,
                port,
                0x02, // SYN
                60,
            )?;
        } else if roll < 30 && !heavy_pairs.is_empty() {
            // Heavy talker: large flows between fixed pairs.
            let (src, dst) = heavy_pairs[(rng.next() % heavy_pairs.len() as u64) as usize];
            w.write_tcp_packet(
                ts,
                IpAddr::V4(src),
                IpAddr::V4(dst),
                33_000,
                443,
                0x18, // PSH|ACK
                1_200 + (rng.next() % 200) as u32,
            )?;
        } else {
            // Background: modest flows between a moderate host population.
            let src = Ipv4Addr::new(10, 9, (rng.next() % 32) as u8, (rng.next() % 250 + 1) as u8);
            let dst = Ipv4Addr::new(10, 8, (rng.next() % 8) as u8, (rng.next() % 250 + 1) as u8);
            if rng.next() % 4 == 0 {
                w.write_udp_packet(
                    ts,
                    IpAddr::V4(src),
                    IpAddr::V4(dst),
                    50_000 + (rng.next() % 10_000) as u16,
                    53,
                    80,
                )?;
            } else {
                w.write_tcp_packet(
                    ts,
                    IpAddr::V4(src),
                    IpAddr::V4(dst),
                    40_000 + (rng.next() % 20_000) as u16,
                    if rng.next() % 2 == 0 { 443 } else { 80 },
                    0x18,
                    200 + (rng.next() % 800) as u32,
                )?;
            }
        }
    }

    println!(
        "wrote {} packets over {duration_secs}s to {} ({} scanner(s), {} heavy pair(s), seed {seed})",
        w.packets_written(),
        out.display(),
        scanners,
        heavy_talkers,
    );
    Ok(())
}
